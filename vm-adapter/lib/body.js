// Bounded response body reads.
//
// A target is untrusted input. Reading response.text() unbounded lets a hostile
// or broken server stream as much as it likes into the adapter's heap, so every
// read here stops at a byte ceiling and says whether it stopped early.

export async function readCapped(response, maxBytes) {
  if (!response.body) return { text: '', bytes: 0, truncated: false };

  const reader = response.body.getReader();
  const chunks = [];
  let received = 0;
  let truncated = false;

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    received += value.length;
    if (received > maxBytes) {
      truncated = true;
      await reader.cancel();
      break;
    }
  }

  const buffer = Buffer.concat(chunks).subarray(0, maxBytes);
  // Report what was actually kept, not what arrived — a caller showing this as a
  // size must not claim a megabyte it only read the first kilobyte of.
  return { text: buffer.toString('utf8'), bytes: buffer.length, truncated };
}