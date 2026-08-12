/** Returns a prefix that does not end inside a valid UTF-8 sequence. */
export function completeUtf8PrefixLength(buffer: Uint8Array): number {
  if (buffer.length === 0) {
    return 0;
  }

  let leadIndex = buffer.length - 1;
  let continuationBytes = 0;
  while (
    leadIndex >= 0 &&
    continuationBytes < 3 &&
    (buffer[leadIndex]! & 0xc0) === 0x80
  ) {
    continuationBytes += 1;
    leadIndex -= 1;
  }
  if (leadIndex < 0) {
    return buffer.length;
  }

  const lead = buffer[leadIndex]!;
  const expectedBytes =
    lead <= 0x7f
      ? 1
      : lead >= 0xc2 && lead <= 0xdf
        ? 2
        : lead >= 0xe0 && lead <= 0xef
          ? 3
          : lead >= 0xf0 && lead <= 0xf4
            ? 4
            : 1;
  const availableBytes = buffer.length - leadIndex;
  return expectedBytes > availableBytes && continuationBytes === availableBytes - 1
    ? leadIndex
    : buffer.length;
}
