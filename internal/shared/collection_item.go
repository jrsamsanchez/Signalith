package shared

// Item returns a copy of the item name with its version and who changed
// it last, where and when.
func (c *Collection[T]) Item(name string) (Item[T], bool) {
	c.mu.Lock()
	e := c.items[c.ItemID(name)]
	c.mu.Unlock()
	if e == nil || e.env.Deleted {
		return Item[T]{}, false
	}
	v, err := decodeBody[T](e.env.Body)
	if err != nil {
		return Item[T]{}, false
	}
	return Item[T]{Name: name, Value: v, ETag: e.etag(), UpdatedBy: e.env.UpdatedBy, UpdatedAt: e.env.UpdatedAt}, true
}
