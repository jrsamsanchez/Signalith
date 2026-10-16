package notify

import (
	"context"
	"errors"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// ErrAlreadySent is SendOnce's error when the finding already went to the
// channel, or is going there now, from a rule or a playbook.
var ErrAlreadySent = errors.New("this finding was already sent to this channel")

// SendOnce sends a playbook's message about a finding to a channel, unless
// the finding went there before. It claims the same delivery the
// dispatcher would, DeliveryID(finding, channel), so a playbook step and
// a rule that both send a finding to one channel send it once, whichever
// comes first. The delivery shows in the recent deliveries; a failed one
// is tried again by the dispatcher, as a rule's would be.
//
// The error is ErrAlreadySent when the finding went there before, or the
// SendError, in words for people; again is true when a failed message is
// tried again later.
func SendOnce(ctx context.Context, sender Sender, deliveries Deliveries, c Channel, m Message, playbook, server string, now func() time.Time) (again bool, err error) {
	if now == nil {
		now = time.Now
	}
	start := now()
	del := &Delivery{
		ID: DeliveryID(m.FindingID, c.ID), Kind: KindFinding, FindingID: m.FindingID,
		Channel: c.ID, ChannelName: c.Name, ChannelType: c.Type, Playbook: playbook,
		Status: StatusSending, Attempts: 1, Message: m, Server: server,
		Created: start, Updated: start, Claimed: start,
	}
	v, err := deliveries.Claim(ctx, del)
	if errors.Is(err, store.ErrExists) {
		return false, ErrAlreadySent
	}
	if err != nil {
		return false, err
	}
	err = sender.Send(ctx, c, m)
	end := now()
	del.DurationMS = end.Sub(start).Milliseconds()
	settle(del, err, end)
	// Written whatever happens to ctx: the message went out or not.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	_, werr := deliveries.Update(wctx, del, v)
	cancel()
	return err != nil && werr == nil && del.NextTry != nil, err
}
