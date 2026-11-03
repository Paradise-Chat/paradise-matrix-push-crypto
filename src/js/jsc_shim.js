// src/js/jsc_shim.js
// Polyfills for running wasm-bindgen + wasm2js inside a bare iOS JSContext

(function (global) {
  "use strict";

  // Console stub (JSContext has no console object by default)
  if (typeof global.console === "undefined") {
    global.console = {
      log: function () {},
      warn: function () {},
      error: function () {},
    };
  }

  // UTF-8 TextEncoder (required by wasm-bindgen string marshaling)
  if (typeof global.TextEncoder === "undefined") {
    class TextEncoder {
      constructor() {
        this.encoding = "utf-8";
      }

      encode(str = "") {
        const bytes = [];
        for (let i = 0; i < str.length; i++) {
          let codePoint = str.charCodeAt(i);

          // Handle UTF-16 surrogate pairs (e.g. emojis in Matrix messages)
          if (codePoint >= 0xd800 && codePoint <= 0xdbff && i + 1 < str.length) {
            const next = str.charCodeAt(i + 1);
            if (next >= 0xdc00 && next <= 0xdfff) {
              codePoint = ((codePoint - 0xd800) << 10) + (next - 0xdc00) + 0x10000;
              i++;
            }
          }

          if (codePoint <= 0x7f) {
            bytes.push(codePoint);
          } else if (codePoint <= 0x7ff) {
            bytes.push(
              0xc0 | (codePoint >> 6),
              0x80 | (codePoint & 0x3f)
            );
          } else if (codePoint <= 0xffff) {
            bytes.push(
              0xe0 | (codePoint >> 12),
              0x80 | ((codePoint >> 6) & 0x3f),
              0x80 | (codePoint & 0x3f)
            );
          } else {
            bytes.push(
              0xf0 | (codePoint >> 18),
              0x80 | ((codePoint >> 12) & 0x3f),
              0x80 | ((codePoint >> 6) & 0x3f),
              0x80 | (codePoint & 0x3f)
            );
          }
        }
        return new Uint8Array(bytes);
      }

      // Direct write into Wasm linear memory (avoids intermediate Uint8Array allocation)
      encodeInto(str, dest) {
        let read = 0;
        let written = 0;
        const len = str.length;
        const max = dest.length;

        while (read < len) {
          let codePoint = str.charCodeAt(read);
          let charLen = 1;

          if (codePoint >= 0xd800 && codePoint <= 0xdbff && read + 1 < len) {
            const next = str.charCodeAt(read + 1);
            if (next >= 0xdc00 && next <= 0xdfff) {
              codePoint = ((codePoint - 0xd800) << 10) + (next - 0xdc00) + 0x10000;
              charLen = 2;
            }
          }

          if (codePoint <= 0x7f) {
            if (written + 1 > max) break;
            dest[written++] = codePoint;
          } else if (codePoint <= 0x7ff) {
            if (written + 2 > max) break;
            dest[written++] = 0xc0 | (codePoint >> 6);
            dest[written++] = 0x80 | (codePoint & 0x3f);
          } else if (codePoint <= 0xffff) {
            if (written + 3 > max) break;
            dest[written++] = 0xe0 | (codePoint >> 12);
            dest[written++] = 0x80 | ((codePoint >> 6) & 0x3f);
            dest[written++] = 0x80 | (codePoint & 0x3f);
          } else {
            if (written + 4 > max) break;
            dest[written++] = 0xf0 | (codePoint >> 18);
            dest[written++] = 0x80 | ((codePoint >> 12) & 0x3f);
            dest[written++] = 0x80 | ((codePoint >> 6) & 0x3f);
            dest[written++] = 0x80 | (codePoint & 0x3f);
          }
          read += charLen;
        }

        return { read, written };
      }
    }

    global.TextEncoder = TextEncoder;
  }

  // UTF-8 TextDecoder (required by wasm-bindgen to read strings/errors from Wasm memory)
  if (typeof global.TextDecoder === "undefined") {
    class TextDecoder {
      constructor() {
        this.encoding = "utf-8";
      }

      decode(input) {
        if (!input) return "";
        const bytes =
          input instanceof Uint8Array
            ? input
            : new Uint8Array(input.buffer || input, input.byteOffset || 0, input.byteLength);

        let out = "";
        const chunk = [];
        let i = 0;
        const len = bytes.length;

        while (i < len) {
          const b1 = bytes[i++];
          let codePoint;

          if ((b1 & 0x80) === 0) {
            codePoint = b1;
          } else if ((b1 & 0xe0) === 0xc0) {
            const b2 = bytes[i++] & 0x3f;
            codePoint = ((b1 & 0x1f) << 6) | b2;
          } else if ((b1 & 0xf0) === 0xe0) {
            const b2 = bytes[i++] & 0x3f;
            const b3 = bytes[i++] & 0x3f;
            codePoint = ((b1 & 0x0f) << 12) | (b2 << 6) | b3;
          } else {
            const b2 = bytes[i++] & 0x3f;
            const b3 = bytes[i++] & 0x3f;
            const b4 = bytes[i++] & 0x3f;
            codePoint = ((b1 & 0x07) << 18) | (b2 << 12) | (b3 << 6) | b4;
          }

          chunk.push(codePoint);
          // Flush in 4096-codepoint batches to stay well below JSC's 65,536 argument limit
          if (chunk.length >= 4096) {
            out += String.fromCodePoint.apply(null, chunk);
            chunk.length = 0;
          }
        }

        if (chunk.length > 0) {
          out += String.fromCodePoint.apply(null, chunk);
        }

        return out;
      }
    }

    global.TextDecoder = TextDecoder;
  }

  // crypto.getRandomValues (required by Rust's getrandom crate)
  if (typeof global.crypto === "undefined") {
    global.crypto = {};
  }

  if (typeof global.crypto.getRandomValues === "undefined") {
    global.crypto.getRandomValues = function (typedArray) {
      // Preferred: Call into Swift's SecRandomCopyBytes bridge if registered on JSContext
      if (typeof global.__ nativeGetRandomBytes === "function") {
        const randomBytes = global.__nativeGetRandomBytes(typedArray.byteLength);
        const uint8View = new Uint8Array(
          typedArray.buffer,
          typedArray.byteOffset,
          typedArray.byteLength
        );
        uint8View.set(randomBytes);
        return typedArray;
      }

      throw new Error(
        "crypto.getRandomValues called, but __nativeGetRandomBytes is not registered in JSContext"
      );
    };
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
