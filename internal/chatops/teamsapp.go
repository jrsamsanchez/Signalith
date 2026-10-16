package chatops

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"net/url"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/notify"
)

// A Teams app is a zip file with a manifest and two icons, which an admin
// uploads in Teams (Apps > Manage your apps > Upload an app) and adds to a
// team. Signalith makes it for a Teams app channel, with the channel's
// bot.
// https://learn.microsoft.com/microsoftteams/platform/resources/schema/manifest-schema

// teamsAccent is the app's color in Teams.
var teamsAccent = color.RGBA{R: 0x25, G: 0x63, B: 0xeb, A: 0xff}

// TeamsAppPackage returns the Teams app of a Teams app channel, for the
// Signalith at publicURL.
func TeamsAppPackage(c notify.Channel, publicURL string) ([]byte, error) {
	site := "https://signalith.io"
	var domains []string
	if u, err := url.Parse(strings.TrimSpace(publicURL)); err == nil && u.Scheme == "https" && u.Host != "" {
		site = u.Scheme + "://" + u.Host
		domains = append(domains, u.Hostname())
	}
	full := "Signalith: " + c.Name
	if len([]rune(full)) > 100 {
		full = string([]rune(full)[:100])
	}
	manifest := map[string]any{
		"$schema":         "https://developer.microsoft.com/en-us/json-schemas/teams/v1.17/MicrosoftTeams.schema.json",
		"manifestVersion": "1.17",
		"version":         "1.0.0",
		"id":              c.AppID,
		"developer": map[string]any{
			"name": "Signalith", "websiteUrl": site, "privacyUrl": site, "termsOfUseUrl": site,
		},
		"name": map[string]any{"short": "Signalith", "full": full},
		"description": map[string]any{
			"short": "Findings and playbook approvals from Signalith.",
			"full": "Posts Signalith findings and playbook approval requests to a channel. Analysts acknowledge findings and approve or reject " +
				"playbook steps with the buttons, once they link their Teams account to their Signalith user.",
		},
		"icons":       map[string]any{"color": "color.png", "outline": "outline.png"},
		"accentColor": "#2563EB",
		"bots": []any{map[string]any{
			"botId": c.AppID, "scopes": []string{"team", "groupChat", "personal"}, "isNotificationOnly": false, "supportsFiles": false,
			"commandLists": []any{
				map[string]any{"scopes": []string{"team", "groupChat"}, "commands": []any{
					map[string]any{"title": "post here", "description": "Admins: post this channel's Signalith messages here"},
				}},
				// Link codes are sent in a private chat, where nobody else
				// sees them.
				map[string]any{"scopes": []string{"personal"}, "commands": []any{
					map[string]any{"title": "link", "description": "Link your Teams account with a code from Signalith"},
				}},
			},
		}},
		"permissions":  []string{"identity", "messageTeamMembers"},
		"validDomains": domains,
	}
	if domains == nil {
		manifest["validDomains"] = []string{}
	}
	mj, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range map[string][]byte{"manifest.json": mj, "color.png": icon(192, true), "outline.png": icon(32, false)} {
		f, err := zw.Create(name)
		if err != nil {
			return nil, err
		}
		if _, err := f.Write(data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// icon draws the app's icon: three rising bars, white, on the accent color
// (the color icon) or on nothing (the outline icon Teams asks for).
func icon(size int, filled bool) []byte {
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	white := color.RGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff}
	if filled {
		for y := 0; y < size; y++ {
			for x := 0; x < size; x++ {
				img.Set(x, y, teamsAccent)
			}
		}
	}
	unit := size / 8
	for i, h := range []int{2, 4, 6} {
		x0 := unit + i*unit*2 + unit/2
		for y := size - unit - h*unit; y < size-unit; y++ {
			for x := x0; x < x0+unit; x++ {
				img.Set(x, y, white)
			}
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}
