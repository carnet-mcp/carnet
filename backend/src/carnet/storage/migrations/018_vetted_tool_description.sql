-- What a vetted tool says about itself, and what the reviewer wants said about it.
--
-- MCP servers advertise a description in `tools/list`, so the text exists — behind a
-- connection. Reading it when somebody is choosing a tool would make a page about
-- *choosing* depend on every vetted server being *up*, and it would let the wording
-- change under a grant somebody already approved.
--
-- So it is captured at vetting time and stored, which is the move `remote_name` and
-- `effect` already make on this table: the row is the review record, and what the
-- reviewer read is part of what they reviewed. A description that can change after
-- approval is a description that was not part of the approval.
--
-- Two columns rather than one, because they answer different questions and collapsing
-- them loses which of the two you are reading:
--
--   description   the vendor's own words, copied from what the server advertised
--   note          what somebody here should know before granting it
--
-- This is the one place a self-declared string is fine. A description is not a
-- security claim; `effect` is, and `effect` is still ours. `readOnlyHint` remains
-- ignored for the reason migration 003 gives.
--
-- Both default to '' rather than NULL. Every row that exists today was written before
-- there was anywhere to put a sentence, so "not recorded" is the truth about all of
-- them — and an empty string says that without every reader having to handle a null.

ALTER TABLE vetted_tools
    ADD COLUMN description TEXT NOT NULL DEFAULT '',
    ADD COLUMN note        TEXT NOT NULL DEFAULT '';
