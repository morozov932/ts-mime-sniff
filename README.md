# ts-mime-sniff

Identify a file's MIME type from the leading bytes of its content, ignoring the filename. Pass a `Uint8Array` slice of the file head; get back a MIME type string.

```js
import { sniffMimeType } from 'ts-mime-sniff';

const head = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
sniffMimeType(head); // 'image/png'
```

## Why

Filename extensions lie. A `.png` can be a JPEG and an upload form that trusts the client-reported name will mislabel content. Sniffing the magic bytes at the head of the stream is the reliable minimum. This library implements the subset of the WHATWG sniffing spec that is unambiguous: exact byte patterns with no context-dependent overrides. It deliberately does not implement the spec's "unknown type → image" or "markup vs. plain text" heuristics, which require longer reads and produce non-deterministic-looking results for short inputs. What you see here is what you get.

## Edge cases

The sniffer reads at most 12 bytes, matching the longest supported magic (PDF). Pass fewer bytes and the missing positions are treated as zeros, so a prefix shorter than a magic will not spuriously match. An empty input, or bytes that match no known magic, return `application/octet-stream` — not `null`. Throw a `TypeError` if you pass something other than a `Uint8Array`.
