var __noble_boot = (() => {
  var __defProp = Object.defineProperty;
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __esm = (fn, res, err2) => function __init() {
    if (err2) throw err2[0];
    try {
      return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
    } catch (e) {
      throw err2 = [e], e;
    }
  };
  var __commonJS = (cb, mod) => function __require() {
    try {
      return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
    } catch (e) {
      throw mod = 0, e;
    }
  };
  var __export = (target, all) => {
    for (var name in all)
      __defProp(target, name, { get: all[name], enumerable: true });
  };

  // node_modules/@noble/ed25519/index.js
  var ed25519_exports = {};
  __export(ed25519_exports, {
    CURVE: () => ed25519_CURVE,
    ExtendedPoint: () => Point,
    Point: () => Point,
    etc: () => etc,
    getPublicKey: () => getPublicKey,
    getPublicKeyAsync: () => getPublicKeyAsync,
    sign: () => sign,
    signAsync: () => signAsync,
    utils: () => utils,
    verify: () => verify,
    verifyAsync: () => verifyAsync
  });
  var ed25519_CURVE, P, N, Gx, Gy, _a, _d, h, L, L2, err, isBig, isStr, isBytes, abytes, u8n, u8fr, padh, bytesToHex, C, _ch, hexToBytes, toU8, cr, subtle, concatBytes, randomBytes, big, arange, M, modN, invert, callHash, apoint, B256, Point, G, I, numTo32bLE, bytesToNumLE, pow2, pow_2_252_3, RM1, uvRatio, modL_LE, sha512a, sha512s, hash2extK, getExtendedPublicKeyAsync, getExtendedPublicKey, getPublicKeyAsync, getPublicKey, hashFinishA, hashFinishS, _sign, signAsync, sign, veriOpts, _verify, verifyAsync, verify, etc, utils, W, scalarBits, pwindows, pwindowSize, precompute, Gpows, ctneg, wNAF;
  var init_ed25519 = __esm({
    "node_modules/@noble/ed25519/index.js"() {
      /*! noble-ed25519 - MIT License (c) 2019 Paul Miller (paulmillr.com) */
      ed25519_CURVE = {
        p: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffedn,
        n: 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn,
        h: 8n,
        a: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffecn,
        d: 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3n,
        Gx: 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51an,
        Gy: 0x6666666666666666666666666666666666666666666666666666666666666658n
      };
      ({ p: P, n: N, Gx, Gy, a: _a, d: _d } = ed25519_CURVE);
      h = 8n;
      L = 32;
      L2 = 64;
      err = (m = "") => {
        throw new Error(m);
      };
      isBig = (n) => typeof n === "bigint";
      isStr = (s) => typeof s === "string";
      isBytes = (a) => a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
      abytes = (a, l) => !isBytes(a) || typeof l === "number" && l > 0 && a.length !== l ? err("Uint8Array expected") : a;
      u8n = (len) => new Uint8Array(len);
      u8fr = (buf) => Uint8Array.from(buf);
      padh = (n, pad) => n.toString(16).padStart(pad, "0");
      bytesToHex = (b) => Array.from(abytes(b)).map((e) => padh(e, 2)).join("");
      C = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
      _ch = (ch) => {
        if (ch >= C._0 && ch <= C._9)
          return ch - C._0;
        if (ch >= C.A && ch <= C.F)
          return ch - (C.A - 10);
        if (ch >= C.a && ch <= C.f)
          return ch - (C.a - 10);
        return;
      };
      hexToBytes = (hex) => {
        const e = "hex invalid";
        if (!isStr(hex))
          return err(e);
        const hl = hex.length;
        const al = hl / 2;
        if (hl % 2)
          return err(e);
        const array = u8n(al);
        for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
          const n1 = _ch(hex.charCodeAt(hi));
          const n2 = _ch(hex.charCodeAt(hi + 1));
          if (n1 === void 0 || n2 === void 0)
            return err(e);
          array[ai] = n1 * 16 + n2;
        }
        return array;
      };
      toU8 = (a, len) => abytes(isStr(a) ? hexToBytes(a) : u8fr(abytes(a)), len);
      cr = () => globalThis?.crypto;
      subtle = () => cr()?.subtle ?? err("crypto.subtle must be defined");
      concatBytes = (...arrs) => {
        const r = u8n(arrs.reduce((sum, a) => sum + abytes(a).length, 0));
        let pad = 0;
        arrs.forEach((a) => {
          r.set(a, pad);
          pad += a.length;
        });
        return r;
      };
      randomBytes = (len = L) => {
        const c = cr();
        return c.getRandomValues(u8n(len));
      };
      big = BigInt;
      arange = (n, min, max, msg = "bad number: out of range") => isBig(n) && min <= n && n < max ? n : err(msg);
      M = (a, b = P) => {
        const r = a % b;
        return r >= 0n ? r : b + r;
      };
      modN = (a) => M(a, N);
      invert = (num, md) => {
        if (num === 0n || md <= 0n)
          err("no inverse n=" + num + " mod=" + md);
        let a = M(num, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
        while (a !== 0n) {
          const q = b / a, r = b % a;
          const m = x - u * q, n = y - v * q;
          b = a, a = r, x = u, y = v, u = m, v = n;
        }
        return b === 1n ? M(x, md) : err("no inverse");
      };
      callHash = (name) => {
        const fn = etc[name];
        if (typeof fn !== "function")
          err("hashes." + name + " not set");
        return fn;
      };
      apoint = (p) => p instanceof Point ? p : err("Point expected");
      B256 = 2n ** 256n;
      Point = class _Point {
        static BASE;
        static ZERO;
        ex;
        ey;
        ez;
        et;
        constructor(ex, ey, ez, et) {
          const max = B256;
          this.ex = arange(ex, 0n, max);
          this.ey = arange(ey, 0n, max);
          this.ez = arange(ez, 1n, max);
          this.et = arange(et, 0n, max);
          Object.freeze(this);
        }
        static fromAffine(p) {
          return new _Point(p.x, p.y, 1n, M(p.x * p.y));
        }
        /** RFC8032 5.1.3: Uint8Array to Point. */
        static fromBytes(hex, zip215 = false) {
          const d = _d;
          const normed = u8fr(abytes(hex, L));
          const lastByte = hex[31];
          normed[31] = lastByte & ~128;
          const y = bytesToNumLE(normed);
          const max = zip215 ? B256 : P;
          arange(y, 0n, max);
          const y2 = M(y * y);
          const u = M(y2 - 1n);
          const v = M(d * y2 + 1n);
          let { isValid, value: x } = uvRatio(u, v);
          if (!isValid)
            err("bad point: y not sqrt");
          const isXOdd = (x & 1n) === 1n;
          const isLastByteOdd = (lastByte & 128) !== 0;
          if (!zip215 && x === 0n && isLastByteOdd)
            err("bad point: x==0, isLastByteOdd");
          if (isLastByteOdd !== isXOdd)
            x = M(-x);
          return new _Point(x, y, 1n, M(x * y));
        }
        /** Checks if the point is valid and on-curve. */
        assertValidity() {
          const a = _a;
          const d = _d;
          const p = this;
          if (p.is0())
            throw new Error("bad point: ZERO");
          const { ex: X, ey: Y, ez: Z, et: T } = p;
          const X2 = M(X * X);
          const Y2 = M(Y * Y);
          const Z2 = M(Z * Z);
          const Z4 = M(Z2 * Z2);
          const aX2 = M(X2 * a);
          const left = M(Z2 * M(aX2 + Y2));
          const right = M(Z4 + M(d * M(X2 * Y2)));
          if (left !== right)
            throw new Error("bad point: equation left != right (1)");
          const XY = M(X * Y);
          const ZT = M(Z * T);
          if (XY !== ZT)
            throw new Error("bad point: equation left != right (2)");
          return this;
        }
        /** Equality check: compare points P&Q. */
        equals(other) {
          const { ex: X1, ey: Y1, ez: Z1 } = this;
          const { ex: X2, ey: Y2, ez: Z2 } = apoint(other);
          const X1Z2 = M(X1 * Z2);
          const X2Z1 = M(X2 * Z1);
          const Y1Z2 = M(Y1 * Z2);
          const Y2Z1 = M(Y2 * Z1);
          return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
        }
        is0() {
          return this.equals(I);
        }
        /** Flip point over y coordinate. */
        negate() {
          return new _Point(M(-this.ex), this.ey, this.ez, M(-this.et));
        }
        /** Point doubling. Complete formula. Cost: `4M + 4S + 1*a + 6add + 1*2`. */
        double() {
          const { ex: X1, ey: Y1, ez: Z1 } = this;
          const a = _a;
          const A = M(X1 * X1);
          const B = M(Y1 * Y1);
          const C2 = M(2n * M(Z1 * Z1));
          const D = M(a * A);
          const x1y1 = X1 + Y1;
          const E = M(M(x1y1 * x1y1) - A - B);
          const G2 = D + B;
          const F = G2 - C2;
          const H = D - B;
          const X3 = M(E * F);
          const Y3 = M(G2 * H);
          const T3 = M(E * H);
          const Z3 = M(F * G2);
          return new _Point(X3, Y3, Z3, T3);
        }
        /** Point addition. Complete formula. Cost: `8M + 1*k + 8add + 1*2`. */
        add(other) {
          const { ex: X1, ey: Y1, ez: Z1, et: T1 } = this;
          const { ex: X2, ey: Y2, ez: Z2, et: T2 } = apoint(other);
          const a = _a;
          const d = _d;
          const A = M(X1 * X2);
          const B = M(Y1 * Y2);
          const C2 = M(T1 * d * T2);
          const D = M(Z1 * Z2);
          const E = M((X1 + Y1) * (X2 + Y2) - A - B);
          const F = M(D - C2);
          const G2 = M(D + C2);
          const H = M(B - a * A);
          const X3 = M(E * F);
          const Y3 = M(G2 * H);
          const T3 = M(E * H);
          const Z3 = M(F * G2);
          return new _Point(X3, Y3, Z3, T3);
        }
        /**
         * Point-by-scalar multiplication. Scalar must be in range 1 <= n < CURVE.n.
         * Uses {@link wNAF} for base point.
         * Uses fake point to mitigate side-channel leakage.
         * @param n scalar by which point is multiplied
         * @param safe safe mode guards against timing attacks; unsafe mode is faster
         */
        multiply(n, safe = true) {
          if (!safe && (n === 0n || this.is0()))
            return I;
          arange(n, 1n, N);
          if (n === 1n)
            return this;
          if (this.equals(G))
            return wNAF(n).p;
          let p = I;
          let f = G;
          for (let d = this; n > 0n; d = d.double(), n >>= 1n) {
            if (n & 1n)
              p = p.add(d);
            else if (safe)
              f = f.add(d);
          }
          return p;
        }
        /** Convert point to 2d xy affine point. (X, Y, Z) ∋ (x=X/Z, y=Y/Z) */
        toAffine() {
          const { ex: x, ey: y, ez: z } = this;
          if (this.equals(I))
            return { x: 0n, y: 1n };
          const iz = invert(z, P);
          if (M(z * iz) !== 1n)
            err("invalid inverse");
          return { x: M(x * iz), y: M(y * iz) };
        }
        toBytes() {
          const { x, y } = this.assertValidity().toAffine();
          const b = numTo32bLE(y);
          b[31] |= x & 1n ? 128 : 0;
          return b;
        }
        toHex() {
          return bytesToHex(this.toBytes());
        }
        // encode to hex string
        clearCofactor() {
          return this.multiply(big(h), false);
        }
        isSmallOrder() {
          return this.clearCofactor().is0();
        }
        isTorsionFree() {
          let p = this.multiply(N / 2n, false).double();
          if (N % 2n)
            p = p.add(this);
          return p.is0();
        }
        static fromHex(hex, zip215) {
          return _Point.fromBytes(toU8(hex), zip215);
        }
        get x() {
          return this.toAffine().x;
        }
        get y() {
          return this.toAffine().y;
        }
        toRawBytes() {
          return this.toBytes();
        }
      };
      G = new Point(Gx, Gy, 1n, M(Gx * Gy));
      I = new Point(0n, 1n, 1n, 0n);
      Point.BASE = G;
      Point.ZERO = I;
      numTo32bLE = (num) => hexToBytes(padh(arange(num, 0n, B256), L2)).reverse();
      bytesToNumLE = (b) => big("0x" + bytesToHex(u8fr(abytes(b)).reverse()));
      pow2 = (x, power) => {
        let r = x;
        while (power-- > 0n) {
          r *= r;
          r %= P;
        }
        return r;
      };
      pow_2_252_3 = (x) => {
        const x2 = x * x % P;
        const b2 = x2 * x % P;
        const b4 = pow2(b2, 2n) * b2 % P;
        const b5 = pow2(b4, 1n) * x % P;
        const b10 = pow2(b5, 5n) * b5 % P;
        const b20 = pow2(b10, 10n) * b10 % P;
        const b40 = pow2(b20, 20n) * b20 % P;
        const b80 = pow2(b40, 40n) * b40 % P;
        const b160 = pow2(b80, 80n) * b80 % P;
        const b240 = pow2(b160, 80n) * b80 % P;
        const b250 = pow2(b240, 10n) * b10 % P;
        const pow_p_5_8 = pow2(b250, 2n) * x % P;
        return { pow_p_5_8, b2 };
      };
      RM1 = 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0n;
      uvRatio = (u, v) => {
        const v3 = M(v * v * v);
        const v7 = M(v3 * v3 * v);
        const pow = pow_2_252_3(u * v7).pow_p_5_8;
        let x = M(u * v3 * pow);
        const vx2 = M(v * x * x);
        const root1 = x;
        const root2 = M(x * RM1);
        const useRoot1 = vx2 === u;
        const useRoot2 = vx2 === M(-u);
        const noRoot = vx2 === M(-u * RM1);
        if (useRoot1)
          x = root1;
        if (useRoot2 || noRoot)
          x = root2;
        if ((M(x) & 1n) === 1n)
          x = M(-x);
        return { isValid: useRoot1 || useRoot2, value: x };
      };
      modL_LE = (hash) => modN(bytesToNumLE(hash));
      sha512a = (...m) => etc.sha512Async(...m);
      sha512s = (...m) => callHash("sha512Sync")(...m);
      hash2extK = (hashed) => {
        const head = hashed.slice(0, L);
        head[0] &= 248;
        head[31] &= 127;
        head[31] |= 64;
        const prefix = hashed.slice(L, L2);
        const scalar = modL_LE(head);
        const point = G.multiply(scalar);
        const pointBytes = point.toBytes();
        return { head, prefix, scalar, point, pointBytes };
      };
      getExtendedPublicKeyAsync = (priv) => sha512a(toU8(priv, L)).then(hash2extK);
      getExtendedPublicKey = (priv) => hash2extK(sha512s(toU8(priv, L)));
      getPublicKeyAsync = (priv) => getExtendedPublicKeyAsync(priv).then((p) => p.pointBytes);
      getPublicKey = (priv) => getExtendedPublicKey(priv).pointBytes;
      hashFinishA = (res) => sha512a(res.hashable).then(res.finish);
      hashFinishS = (res) => res.finish(sha512s(res.hashable));
      _sign = (e, rBytes, msg) => {
        const { pointBytes: P2, scalar: s } = e;
        const r = modL_LE(rBytes);
        const R = G.multiply(r).toBytes();
        const hashable = concatBytes(R, P2, msg);
        const finish = (hashed) => {
          const S = modN(r + modL_LE(hashed) * s);
          return abytes(concatBytes(R, numTo32bLE(S)), L2);
        };
        return { hashable, finish };
      };
      signAsync = async (msg, privKey) => {
        const m = toU8(msg);
        const e = await getExtendedPublicKeyAsync(privKey);
        const rBytes = await sha512a(e.prefix, m);
        return hashFinishA(_sign(e, rBytes, m));
      };
      sign = (msg, privKey) => {
        const m = toU8(msg);
        const e = getExtendedPublicKey(privKey);
        const rBytes = sha512s(e.prefix, m);
        return hashFinishS(_sign(e, rBytes, m));
      };
      veriOpts = { zip215: true };
      _verify = (sig, msg, pub, opts = veriOpts) => {
        sig = toU8(sig, L2);
        msg = toU8(msg);
        pub = toU8(pub, L);
        const { zip215 } = opts;
        let A;
        let R;
        let s;
        let SB;
        let hashable = Uint8Array.of();
        try {
          A = Point.fromHex(pub, zip215);
          R = Point.fromHex(sig.slice(0, L), zip215);
          s = bytesToNumLE(sig.slice(L, L2));
          SB = G.multiply(s, false);
          hashable = concatBytes(R.toBytes(), A.toBytes(), msg);
        } catch (error) {
        }
        const finish = (hashed) => {
          if (SB == null)
            return false;
          if (!zip215 && A.isSmallOrder())
            return false;
          const k = modL_LE(hashed);
          const RkA = R.add(A.multiply(k, false));
          return RkA.add(SB.negate()).clearCofactor().is0();
        };
        return { hashable, finish };
      };
      verifyAsync = async (s, m, p, opts = veriOpts) => hashFinishA(_verify(s, m, p, opts));
      verify = (s, m, p, opts = veriOpts) => hashFinishS(_verify(s, m, p, opts));
      etc = {
        sha512Async: async (...messages) => {
          const s = subtle();
          const m = concatBytes(...messages);
          return u8n(await s.digest("SHA-512", m.buffer));
        },
        sha512Sync: void 0,
        bytesToHex,
        hexToBytes,
        concatBytes,
        mod: M,
        invert,
        randomBytes
      };
      utils = {
        getExtendedPublicKeyAsync,
        getExtendedPublicKey,
        randomPrivateKey: () => randomBytes(L),
        precompute: (w = 8, p = G) => {
          p.multiply(3n);
          w;
          return p;
        }
        // no-op
      };
      W = 8;
      scalarBits = 256;
      pwindows = Math.ceil(scalarBits / W) + 1;
      pwindowSize = 2 ** (W - 1);
      precompute = () => {
        const points = [];
        let p = G;
        let b = p;
        for (let w = 0; w < pwindows; w++) {
          b = p;
          points.push(b);
          for (let i = 1; i < pwindowSize; i++) {
            b = b.add(p);
            points.push(b);
          }
          p = b.double();
        }
        return points;
      };
      Gpows = void 0;
      ctneg = (cnd, p) => {
        const n = p.negate();
        return cnd ? n : p;
      };
      wNAF = (n) => {
        const comp = Gpows || (Gpows = precompute());
        let p = I;
        let f = G;
        const pow_2_w = 2 ** W;
        const maxNum = pow_2_w;
        const mask = big(pow_2_w - 1);
        const shiftBy = big(W);
        for (let w = 0; w < pwindows; w++) {
          let wbits = Number(n & mask);
          n >>= shiftBy;
          if (wbits > pwindowSize) {
            wbits -= maxNum;
            n += 1n;
          }
          const off = w * pwindowSize;
          const offF = off;
          const offP = off + Math.abs(wbits) - 1;
          const isEven = w % 2 !== 0;
          const isNeg = wbits < 0;
          if (wbits === 0) {
            f = f.add(ctneg(isEven, comp[offF]));
          } else {
            p = p.add(ctneg(isNeg, comp[offP]));
          }
        }
        return { p, f };
      };
    }
  });

  // node_modules/@noble/hashes/esm/utils.js
  function isBytes2(a) {
    return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
  }
  function abytes2(b, ...lengths) {
    if (!isBytes2(b))
      throw new Error("Uint8Array expected");
    if (lengths.length > 0 && !lengths.includes(b.length))
      throw new Error("Uint8Array expected of length " + lengths + ", got length=" + b.length);
  }
  function aexists(instance, checkFinished = true) {
    if (instance.destroyed)
      throw new Error("Hash instance has been destroyed");
    if (checkFinished && instance.finished)
      throw new Error("Hash#digest() has already been called");
  }
  function aoutput(out, instance) {
    abytes2(out);
    const min = instance.outputLen;
    if (out.length < min) {
      throw new Error("digestInto() expects output buffer of length at least " + min);
    }
  }
  function clean(...arrays) {
    for (let i = 0; i < arrays.length; i++) {
      arrays[i].fill(0);
    }
  }
  function createView(arr) {
    return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
  }
  function rotr(word, shift) {
    return word << 32 - shift | word >>> shift;
  }
  function utf8ToBytes(str) {
    if (typeof str !== "string")
      throw new Error("string expected");
    return new Uint8Array(new TextEncoder().encode(str));
  }
  function toBytes(data) {
    if (typeof data === "string")
      data = utf8ToBytes(data);
    abytes2(data);
    return data;
  }
  function createHasher(hashCons) {
    const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
    const tmp = hashCons();
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = () => hashCons();
    return hashC;
  }
  var Hash;
  var init_utils = __esm({
    "node_modules/@noble/hashes/esm/utils.js"() {
      /*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
      Hash = class {
      };
    }
  });

  // node_modules/@noble/hashes/esm/_md.js
  function setBigUint64(view, byteOffset, value, isLE) {
    if (typeof view.setBigUint64 === "function")
      return view.setBigUint64(byteOffset, value, isLE);
    const _32n2 = BigInt(32);
    const _u32_max = BigInt(4294967295);
    const wh = Number(value >> _32n2 & _u32_max);
    const wl = Number(value & _u32_max);
    const h2 = isLE ? 4 : 0;
    const l = isLE ? 0 : 4;
    view.setUint32(byteOffset + h2, wh, isLE);
    view.setUint32(byteOffset + l, wl, isLE);
  }
  function Chi(a, b, c) {
    return a & b ^ ~a & c;
  }
  function Maj(a, b, c) {
    return a & b ^ a & c ^ b & c;
  }
  var HashMD, SHA256_IV, SHA512_IV;
  var init_md = __esm({
    "node_modules/@noble/hashes/esm/_md.js"() {
      init_utils();
      HashMD = class extends Hash {
        constructor(blockLen, outputLen, padOffset, isLE) {
          super();
          this.finished = false;
          this.length = 0;
          this.pos = 0;
          this.destroyed = false;
          this.blockLen = blockLen;
          this.outputLen = outputLen;
          this.padOffset = padOffset;
          this.isLE = isLE;
          this.buffer = new Uint8Array(blockLen);
          this.view = createView(this.buffer);
        }
        update(data) {
          aexists(this);
          data = toBytes(data);
          abytes2(data);
          const { view, buffer, blockLen } = this;
          const len = data.length;
          for (let pos = 0; pos < len; ) {
            const take = Math.min(blockLen - this.pos, len - pos);
            if (take === blockLen) {
              const dataView = createView(data);
              for (; blockLen <= len - pos; pos += blockLen)
                this.process(dataView, pos);
              continue;
            }
            buffer.set(data.subarray(pos, pos + take), this.pos);
            this.pos += take;
            pos += take;
            if (this.pos === blockLen) {
              this.process(view, 0);
              this.pos = 0;
            }
          }
          this.length += data.length;
          this.roundClean();
          return this;
        }
        digestInto(out) {
          aexists(this);
          aoutput(out, this);
          this.finished = true;
          const { buffer, view, blockLen, isLE } = this;
          let { pos } = this;
          buffer[pos++] = 128;
          clean(this.buffer.subarray(pos));
          if (this.padOffset > blockLen - pos) {
            this.process(view, 0);
            pos = 0;
          }
          for (let i = pos; i < blockLen; i++)
            buffer[i] = 0;
          setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
          this.process(view, 0);
          const oview = createView(out);
          const len = this.outputLen;
          if (len % 4)
            throw new Error("_sha2: outputLen should be aligned to 32bit");
          const outLen = len / 4;
          const state = this.get();
          if (outLen > state.length)
            throw new Error("_sha2: outputLen bigger than state");
          for (let i = 0; i < outLen; i++)
            oview.setUint32(4 * i, state[i], isLE);
        }
        digest() {
          const { buffer, outputLen } = this;
          this.digestInto(buffer);
          const res = buffer.slice(0, outputLen);
          this.destroy();
          return res;
        }
        _cloneInto(to) {
          to || (to = new this.constructor());
          to.set(...this.get());
          const { blockLen, buffer, length, finished, destroyed, pos } = this;
          to.destroyed = destroyed;
          to.finished = finished;
          to.length = length;
          to.pos = pos;
          if (length % blockLen)
            to.buffer.set(buffer);
          return to;
        }
        clone() {
          return this._cloneInto();
        }
      };
      SHA256_IV = /* @__PURE__ */ Uint32Array.from([
        1779033703,
        3144134277,
        1013904242,
        2773480762,
        1359893119,
        2600822924,
        528734635,
        1541459225
      ]);
      SHA512_IV = /* @__PURE__ */ Uint32Array.from([
        1779033703,
        4089235720,
        3144134277,
        2227873595,
        1013904242,
        4271175723,
        2773480762,
        1595750129,
        1359893119,
        2917565137,
        2600822924,
        725511199,
        528734635,
        4215389547,
        1541459225,
        327033209
      ]);
    }
  });

  // node_modules/@noble/hashes/esm/_u64.js
  function fromBig(n, le = false) {
    if (le)
      return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
    return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
  }
  function split(lst, le = false) {
    const len = lst.length;
    let Ah = new Uint32Array(len);
    let Al = new Uint32Array(len);
    for (let i = 0; i < len; i++) {
      const { h: h2, l } = fromBig(lst[i], le);
      [Ah[i], Al[i]] = [h2, l];
    }
    return [Ah, Al];
  }
  function add(Ah, Al, Bh, Bl) {
    const l = (Al >>> 0) + (Bl >>> 0);
    return { h: Ah + Bh + (l / 2 ** 32 | 0) | 0, l: l | 0 };
  }
  var U32_MASK64, _32n, shrSH, shrSL, rotrSH, rotrSL, rotrBH, rotrBL, add3L, add3H, add4L, add4H, add5L, add5H;
  var init_u64 = __esm({
    "node_modules/@noble/hashes/esm/_u64.js"() {
      U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
      _32n = /* @__PURE__ */ BigInt(32);
      shrSH = (h2, _l, s) => h2 >>> s;
      shrSL = (h2, l, s) => h2 << 32 - s | l >>> s;
      rotrSH = (h2, l, s) => h2 >>> s | l << 32 - s;
      rotrSL = (h2, l, s) => h2 << 32 - s | l >>> s;
      rotrBH = (h2, l, s) => h2 << 64 - s | l >>> s - 32;
      rotrBL = (h2, l, s) => h2 >>> s - 32 | l << 64 - s;
      add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
      add3H = (low, Ah, Bh, Ch) => Ah + Bh + Ch + (low / 2 ** 32 | 0) | 0;
      add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
      add4H = (low, Ah, Bh, Ch, Dh) => Ah + Bh + Ch + Dh + (low / 2 ** 32 | 0) | 0;
      add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
      add5H = (low, Ah, Bh, Ch, Dh, Eh) => Ah + Bh + Ch + Dh + Eh + (low / 2 ** 32 | 0) | 0;
    }
  });

  // node_modules/@noble/hashes/esm/sha2.js
  var SHA256_K, SHA256_W, SHA256, K512, SHA512_Kh, SHA512_Kl, SHA512_W_H, SHA512_W_L, SHA512, sha256, sha512;
  var init_sha2 = __esm({
    "node_modules/@noble/hashes/esm/sha2.js"() {
      init_md();
      init_u64();
      init_utils();
      SHA256_K = /* @__PURE__ */ Uint32Array.from([
        1116352408,
        1899447441,
        3049323471,
        3921009573,
        961987163,
        1508970993,
        2453635748,
        2870763221,
        3624381080,
        310598401,
        607225278,
        1426881987,
        1925078388,
        2162078206,
        2614888103,
        3248222580,
        3835390401,
        4022224774,
        264347078,
        604807628,
        770255983,
        1249150122,
        1555081692,
        1996064986,
        2554220882,
        2821834349,
        2952996808,
        3210313671,
        3336571891,
        3584528711,
        113926993,
        338241895,
        666307205,
        773529912,
        1294757372,
        1396182291,
        1695183700,
        1986661051,
        2177026350,
        2456956037,
        2730485921,
        2820302411,
        3259730800,
        3345764771,
        3516065817,
        3600352804,
        4094571909,
        275423344,
        430227734,
        506948616,
        659060556,
        883997877,
        958139571,
        1322822218,
        1537002063,
        1747873779,
        1955562222,
        2024104815,
        2227730452,
        2361852424,
        2428436474,
        2756734187,
        3204031479,
        3329325298
      ]);
      SHA256_W = /* @__PURE__ */ new Uint32Array(64);
      SHA256 = class extends HashMD {
        constructor(outputLen = 32) {
          super(64, outputLen, 8, false);
          this.A = SHA256_IV[0] | 0;
          this.B = SHA256_IV[1] | 0;
          this.C = SHA256_IV[2] | 0;
          this.D = SHA256_IV[3] | 0;
          this.E = SHA256_IV[4] | 0;
          this.F = SHA256_IV[5] | 0;
          this.G = SHA256_IV[6] | 0;
          this.H = SHA256_IV[7] | 0;
        }
        get() {
          const { A, B, C: C2, D, E, F, G: G2, H } = this;
          return [A, B, C2, D, E, F, G2, H];
        }
        // prettier-ignore
        set(A, B, C2, D, E, F, G2, H) {
          this.A = A | 0;
          this.B = B | 0;
          this.C = C2 | 0;
          this.D = D | 0;
          this.E = E | 0;
          this.F = F | 0;
          this.G = G2 | 0;
          this.H = H | 0;
        }
        process(view, offset) {
          for (let i = 0; i < 16; i++, offset += 4)
            SHA256_W[i] = view.getUint32(offset, false);
          for (let i = 16; i < 64; i++) {
            const W15 = SHA256_W[i - 15];
            const W2 = SHA256_W[i - 2];
            const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
            const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
            SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
          }
          let { A, B, C: C2, D, E, F, G: G2, H } = this;
          for (let i = 0; i < 64; i++) {
            const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
            const T1 = H + sigma1 + Chi(E, F, G2) + SHA256_K[i] + SHA256_W[i] | 0;
            const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
            const T2 = sigma0 + Maj(A, B, C2) | 0;
            H = G2;
            G2 = F;
            F = E;
            E = D + T1 | 0;
            D = C2;
            C2 = B;
            B = A;
            A = T1 + T2 | 0;
          }
          A = A + this.A | 0;
          B = B + this.B | 0;
          C2 = C2 + this.C | 0;
          D = D + this.D | 0;
          E = E + this.E | 0;
          F = F + this.F | 0;
          G2 = G2 + this.G | 0;
          H = H + this.H | 0;
          this.set(A, B, C2, D, E, F, G2, H);
        }
        roundClean() {
          clean(SHA256_W);
        }
        destroy() {
          this.set(0, 0, 0, 0, 0, 0, 0, 0);
          clean(this.buffer);
        }
      };
      K512 = /* @__PURE__ */ (() => split([
        "0x428a2f98d728ae22",
        "0x7137449123ef65cd",
        "0xb5c0fbcfec4d3b2f",
        "0xe9b5dba58189dbbc",
        "0x3956c25bf348b538",
        "0x59f111f1b605d019",
        "0x923f82a4af194f9b",
        "0xab1c5ed5da6d8118",
        "0xd807aa98a3030242",
        "0x12835b0145706fbe",
        "0x243185be4ee4b28c",
        "0x550c7dc3d5ffb4e2",
        "0x72be5d74f27b896f",
        "0x80deb1fe3b1696b1",
        "0x9bdc06a725c71235",
        "0xc19bf174cf692694",
        "0xe49b69c19ef14ad2",
        "0xefbe4786384f25e3",
        "0x0fc19dc68b8cd5b5",
        "0x240ca1cc77ac9c65",
        "0x2de92c6f592b0275",
        "0x4a7484aa6ea6e483",
        "0x5cb0a9dcbd41fbd4",
        "0x76f988da831153b5",
        "0x983e5152ee66dfab",
        "0xa831c66d2db43210",
        "0xb00327c898fb213f",
        "0xbf597fc7beef0ee4",
        "0xc6e00bf33da88fc2",
        "0xd5a79147930aa725",
        "0x06ca6351e003826f",
        "0x142929670a0e6e70",
        "0x27b70a8546d22ffc",
        "0x2e1b21385c26c926",
        "0x4d2c6dfc5ac42aed",
        "0x53380d139d95b3df",
        "0x650a73548baf63de",
        "0x766a0abb3c77b2a8",
        "0x81c2c92e47edaee6",
        "0x92722c851482353b",
        "0xa2bfe8a14cf10364",
        "0xa81a664bbc423001",
        "0xc24b8b70d0f89791",
        "0xc76c51a30654be30",
        "0xd192e819d6ef5218",
        "0xd69906245565a910",
        "0xf40e35855771202a",
        "0x106aa07032bbd1b8",
        "0x19a4c116b8d2d0c8",
        "0x1e376c085141ab53",
        "0x2748774cdf8eeb99",
        "0x34b0bcb5e19b48a8",
        "0x391c0cb3c5c95a63",
        "0x4ed8aa4ae3418acb",
        "0x5b9cca4f7763e373",
        "0x682e6ff3d6b2b8a3",
        "0x748f82ee5defb2fc",
        "0x78a5636f43172f60",
        "0x84c87814a1f0ab72",
        "0x8cc702081a6439ec",
        "0x90befffa23631e28",
        "0xa4506cebde82bde9",
        "0xbef9a3f7b2c67915",
        "0xc67178f2e372532b",
        "0xca273eceea26619c",
        "0xd186b8c721c0c207",
        "0xeada7dd6cde0eb1e",
        "0xf57d4f7fee6ed178",
        "0x06f067aa72176fba",
        "0x0a637dc5a2c898a6",
        "0x113f9804bef90dae",
        "0x1b710b35131c471b",
        "0x28db77f523047d84",
        "0x32caab7b40c72493",
        "0x3c9ebe0a15c9bebc",
        "0x431d67c49c100d4c",
        "0x4cc5d4becb3e42b6",
        "0x597f299cfc657e2a",
        "0x5fcb6fab3ad6faec",
        "0x6c44198c4a475817"
      ].map((n) => BigInt(n))))();
      SHA512_Kh = /* @__PURE__ */ (() => K512[0])();
      SHA512_Kl = /* @__PURE__ */ (() => K512[1])();
      SHA512_W_H = /* @__PURE__ */ new Uint32Array(80);
      SHA512_W_L = /* @__PURE__ */ new Uint32Array(80);
      SHA512 = class extends HashMD {
        constructor(outputLen = 64) {
          super(128, outputLen, 16, false);
          this.Ah = SHA512_IV[0] | 0;
          this.Al = SHA512_IV[1] | 0;
          this.Bh = SHA512_IV[2] | 0;
          this.Bl = SHA512_IV[3] | 0;
          this.Ch = SHA512_IV[4] | 0;
          this.Cl = SHA512_IV[5] | 0;
          this.Dh = SHA512_IV[6] | 0;
          this.Dl = SHA512_IV[7] | 0;
          this.Eh = SHA512_IV[8] | 0;
          this.El = SHA512_IV[9] | 0;
          this.Fh = SHA512_IV[10] | 0;
          this.Fl = SHA512_IV[11] | 0;
          this.Gh = SHA512_IV[12] | 0;
          this.Gl = SHA512_IV[13] | 0;
          this.Hh = SHA512_IV[14] | 0;
          this.Hl = SHA512_IV[15] | 0;
        }
        // prettier-ignore
        get() {
          const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
          return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
        }
        // prettier-ignore
        set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
          this.Ah = Ah | 0;
          this.Al = Al | 0;
          this.Bh = Bh | 0;
          this.Bl = Bl | 0;
          this.Ch = Ch | 0;
          this.Cl = Cl | 0;
          this.Dh = Dh | 0;
          this.Dl = Dl | 0;
          this.Eh = Eh | 0;
          this.El = El | 0;
          this.Fh = Fh | 0;
          this.Fl = Fl | 0;
          this.Gh = Gh | 0;
          this.Gl = Gl | 0;
          this.Hh = Hh | 0;
          this.Hl = Hl | 0;
        }
        process(view, offset) {
          for (let i = 0; i < 16; i++, offset += 4) {
            SHA512_W_H[i] = view.getUint32(offset);
            SHA512_W_L[i] = view.getUint32(offset += 4);
          }
          for (let i = 16; i < 80; i++) {
            const W15h = SHA512_W_H[i - 15] | 0;
            const W15l = SHA512_W_L[i - 15] | 0;
            const s0h = rotrSH(W15h, W15l, 1) ^ rotrSH(W15h, W15l, 8) ^ shrSH(W15h, W15l, 7);
            const s0l = rotrSL(W15h, W15l, 1) ^ rotrSL(W15h, W15l, 8) ^ shrSL(W15h, W15l, 7);
            const W2h = SHA512_W_H[i - 2] | 0;
            const W2l = SHA512_W_L[i - 2] | 0;
            const s1h = rotrSH(W2h, W2l, 19) ^ rotrBH(W2h, W2l, 61) ^ shrSH(W2h, W2l, 6);
            const s1l = rotrSL(W2h, W2l, 19) ^ rotrBL(W2h, W2l, 61) ^ shrSL(W2h, W2l, 6);
            const SUMl = add4L(s0l, s1l, SHA512_W_L[i - 7], SHA512_W_L[i - 16]);
            const SUMh = add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16]);
            SHA512_W_H[i] = SUMh | 0;
            SHA512_W_L[i] = SUMl | 0;
          }
          let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
          for (let i = 0; i < 80; i++) {
            const sigma1h = rotrSH(Eh, El, 14) ^ rotrSH(Eh, El, 18) ^ rotrBH(Eh, El, 41);
            const sigma1l = rotrSL(Eh, El, 14) ^ rotrSL(Eh, El, 18) ^ rotrBL(Eh, El, 41);
            const CHIh = Eh & Fh ^ ~Eh & Gh;
            const CHIl = El & Fl ^ ~El & Gl;
            const T1ll = add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i]);
            const T1h = add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i]);
            const T1l = T1ll | 0;
            const sigma0h = rotrSH(Ah, Al, 28) ^ rotrBH(Ah, Al, 34) ^ rotrBH(Ah, Al, 39);
            const sigma0l = rotrSL(Ah, Al, 28) ^ rotrBL(Ah, Al, 34) ^ rotrBL(Ah, Al, 39);
            const MAJh = Ah & Bh ^ Ah & Ch ^ Bh & Ch;
            const MAJl = Al & Bl ^ Al & Cl ^ Bl & Cl;
            Hh = Gh | 0;
            Hl = Gl | 0;
            Gh = Fh | 0;
            Gl = Fl | 0;
            Fh = Eh | 0;
            Fl = El | 0;
            ({ h: Eh, l: El } = add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
            Dh = Ch | 0;
            Dl = Cl | 0;
            Ch = Bh | 0;
            Cl = Bl | 0;
            Bh = Ah | 0;
            Bl = Al | 0;
            const All = add3L(T1l, sigma0l, MAJl);
            Ah = add3H(All, T1h, sigma0h, MAJh);
            Al = All | 0;
          }
          ({ h: Ah, l: Al } = add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
          ({ h: Bh, l: Bl } = add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
          ({ h: Ch, l: Cl } = add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
          ({ h: Dh, l: Dl } = add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
          ({ h: Eh, l: El } = add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
          ({ h: Fh, l: Fl } = add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
          ({ h: Gh, l: Gl } = add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
          ({ h: Hh, l: Hl } = add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
          this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
        }
        roundClean() {
          clean(SHA512_W_H, SHA512_W_L);
        }
        destroy() {
          clean(this.buffer);
          this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        }
      };
      sha256 = /* @__PURE__ */ createHasher(() => new SHA256());
      sha512 = /* @__PURE__ */ createHasher(() => new SHA512());
    }
  });

  // node_modules/@noble/hashes/esm/sha512.js
  var sha5122;
  var init_sha512 = __esm({
    "node_modules/@noble/hashes/esm/sha512.js"() {
      init_sha2();
      sha5122 = sha512;
    }
  });

  // node_modules/@noble/hashes/esm/sha256.js
  var sha2562;
  var init_sha256 = __esm({
    "node_modules/@noble/hashes/esm/sha256.js"() {
      init_sha2();
      sha2562 = sha256;
    }
  });

  // entry.js
  var require_entry = __commonJS({
    "entry.js"() {
      init_ed25519();
      init_sha512();
      init_sha256();
      etc.sha512Sync = (...m) => sha5122(etc.concatBytes(...m));
      globalThis.nobleEd25519 = ed25519_exports;
      globalThis.nobleSha256 = sha2562;
    }
  });
  return require_entry();
})();
