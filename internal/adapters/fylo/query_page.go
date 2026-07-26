package fylo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// invalidCursorCode is FYLO's typed code for an invalid, expired, or
// foreign-process query cursor.
const invalidCursorCode = "EINVALIDCURSOR"

// DocumentPage is one bounded page of a cursor-paginated document query. An
// empty NextCursor means the traversal is complete.
type DocumentPage struct {
	Items      map[string]json.RawMessage
	NextCursor string
}

// FindDocsPage retrieves one bounded page of documents from a collection
// query. Pass an empty cursor for the first page and each returned NextCursor
// for the following pages. It fails closed when the runtime does not
// advertise the pagination capability, when the limit is outside the
// negotiated contract, or when the response page is inconsistent with the
// request. Callers must treat IsInvalidCursor failures per FYLO's restart
// policy: discard partial state and restart from the first page.
func (c *Client) FindDocsPage(
	ctx context.Context,
	collection string,
	query map[string]any,
	limit int,
	cursor string,
) (DocumentPage, error) {
	capability := c.identity.Capabilities.QueryPagination
	if capability == nil {
		return DocumentPage{}, errors.New("FYLO runtime does not advertise query pagination")
	}
	if limit < 1 || limit > capability.MaxItems {
		return DocumentPage{}, fmt.Errorf(
			"FYLO page limit %d is outside 1..%d",
			limit,
			capability.MaxItems,
		)
	}

	page := map[string]any{"limit": limit}
	if cursor != "" {
		page["cursor"] = cursor
	}
	var wire struct {
		Items      map[string]json.RawMessage `json:"items"`
		NextCursor *string                    `json:"nextCursor"`
		Page       struct {
			Count int `json:"count"`
			Limit int `json:"limit"`
		} `json:"page"`
	}
	if err := c.Request(ctx, "findDocs", map[string]any{
		"collection": collection,
		"query":      query,
		"page":       page,
	}, &wire); err != nil {
		return DocumentPage{}, err
	}

	if wire.Page.Limit != limit {
		return DocumentPage{}, fmt.Errorf(
			"FYLO page limit mismatch: requested %d, received %d",
			limit,
			wire.Page.Limit,
		)
	}
	if wire.Page.Count != len(wire.Items) {
		return DocumentPage{}, fmt.Errorf(
			"FYLO page count %d does not match %d returned items",
			wire.Page.Count,
			len(wire.Items),
		)
	}
	if len(wire.Items) > limit {
		return DocumentPage{}, fmt.Errorf(
			"FYLO page returned %d items over the %d limit",
			len(wire.Items),
			limit,
		)
	}

	result := DocumentPage{Items: wire.Items}
	if wire.NextCursor != nil {
		if *wire.NextCursor == "" {
			return DocumentPage{}, errors.New("FYLO page continuation cursor is empty")
		}
		result.NextCursor = *wire.NextCursor
	}
	return result, nil
}

// IsInvalidCursor reports whether err is FYLO's typed rejection of an
// invalid, expired, or foreign-process pagination cursor.
func IsInvalidCursor(err error) bool {
	var operationErr *OperationError
	return errors.As(err, &operationErr) && operationErr.Code == invalidCursorCode
}

// FindDocsAll retrieves a complete query result through bounded cursor pages,
// failing closed when a document repeats across pages or the traversal
// exceeds maxPages. FYLO's restart policy for a lost or expired cursor is
// restart-from-first-page, so one full restart is attempted before failing.
// It returns the documents and the number of pages traversed.
func (c *Client) FindDocsAll(
	ctx context.Context,
	collection string,
	query map[string]any,
	limit int,
	maxPages int,
) (map[string]json.RawMessage, int, error) {
	documents, pages, err := c.findDocsTraversal(ctx, collection, query, limit, maxPages)
	if err != nil && IsInvalidCursor(err) {
		documents, pages, err = c.findDocsTraversal(ctx, collection, query, limit, maxPages)
	}
	return documents, pages, err
}

func (c *Client) findDocsTraversal(
	ctx context.Context,
	collection string,
	query map[string]any,
	limit int,
	maxPages int,
) (map[string]json.RawMessage, int, error) {
	if maxPages < 1 {
		return nil, 0, errors.New("FYLO traversal page cap must be positive")
	}
	documents := make(map[string]json.RawMessage)
	cursor := ""
	pages := 0
	for {
		if pages >= maxPages {
			return nil, 0, fmt.Errorf("FYLO traversal exceeded %d pages", maxPages)
		}
		page, err := c.FindDocsPage(ctx, collection, query, limit, cursor)
		if err != nil {
			return nil, 0, err
		}
		pages++
		for id, document := range page.Items {
			if _, exists := documents[id]; exists {
				return nil, 0, fmt.Errorf("document %s appeared on more than one page", id)
			}
			documents[id] = document
		}
		if page.NextCursor == "" {
			return documents, pages, nil
		}
		cursor = page.NextCursor
	}
}
