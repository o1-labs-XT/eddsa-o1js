// Auxiliary function to compute x coordinate from decoded coordinate y and
// parity bit x_0 using the trick to compute the square root of Edwards25519
// x = sqrt ( (y^2 - 1) / (d * y^2 + 1) ) as described in

import {
  assert,
  Bool,
  Bytes,
  AlmostForeignField,
  provableFromClass,
  ProvablePureExtended,
  Gadgets,
} from 'o1js';

import {
  createForeignTwisted,
  Eddsa,
  encode,
  Field3,
  FlexiblePoint,
  ForeignTwisted,
  toPoint,
} from './twisted-curve.js';

import { TwistedCurveParams } from '..';

const { ForeignField, multiRangeCheck } = Gadgets;

export { createEddsa, EddsaSignature };

type FlexibleSignature =
  | EddsaSignature
  | {
      R: AlmostForeignField | Field3 | bigint | number;
      s: AlmostForeignField | Field3 | bigint | number;
    };

class EddsaSignature {
  R: AlmostForeignField;
  s: AlmostForeignField;

  /**
   * Create a new {@link EddsaSignature} from an object containing the scalars R and s.
   *
   * Note: Inputs must be range checked if they originate from a different field
   * with a different modulus or if they are not constants. Please refer to the
   * {@link ForeignField} constructor comments for more details.
   */
  constructor(signature: {
    R: AlmostForeignField | Field3 | bigint | number;
    s: AlmostForeignField | Field3 | bigint | number;
  }) {
    // R is a compressed point encoding (up to 2^256),x larger than both the
    // scalar field (~2^252) and the base field (~2^255). Converting a bigint
    // through any ForeignField constructor would reduce mod the modulus,
    // corrupting the parity bit. Instead, we should always convert to Field3 (raw limbs)
    // first, which bypasses the modular reduction in the ForeignField constructor.
    let R = signature.R;
    if (typeof R === 'bigint' || typeof R === 'number') {
      R = Gadgets.Field3.from(BigInt(R));
    }
    this.R = new this.Constructor.Curve.Field(R);
    this.s = new this.Constructor.Curve.Scalar(signature.s);
  }

  /**
   * Coerce the input to a {@link EddsaSignature}.
   */
  static from(signature: FlexibleSignature): EddsaSignature {
    if (signature instanceof this) return signature;
    return new this(signature);
  }

  /**
   * Create an {@link EddsaSignature} from a raw 130-char hex string
   */
  static fromHex(rawSignature: string): EddsaSignature {
    let S = Eddsa.Signature.fromHex(rawSignature);
    return new this(S);
  }

  /**
   * Convert this signature to an object with bigint fields.
   */
  toBigInt() {
    return { R: this.R.toBigInt(), s: this.s.toBigInt() };
  }

  /**
   * Verify the EdDSA signature given the message (an array of bytes) and public
   * key (a {@link Curve} point).
   *
   * **Important:** This method returns a {@link Bool} which indicates whether
   * the signature is valid. So, to actually prove validity of a signature, you
   * need to assert that the result is true.
   *
   * @throws if one of the signature scalars is zero or if the public key is not
   * on the curve.
   *
   * @example
   * ```ts
   * // create classes for your curve
   * class Edwards25519 extends createForeignCurve(Crypto.TwistedCurveParams.Edwards25519) {}
   * class Scalar extends Edwards25519.Scalar {}
   * class Ed25519 extends createEddsa(Edwards25519) {}
   *
   * let message = 'my message';
   * let messageBytes = new TextEncoder().encode(message);
   *
   * // outside provable code: create inputs
   * let privateKey = Scalar.random();
   * let publicKey = Edwards25519.generator.scale(privateKey);
   * let signature = Ed25519.sign(messageBytes, privateKey.toBigInt());
   *
   * // ...
   * // in provable code: create input witnesses (or use method inputs, or constants)
   * let pk = Provable.witness(Edwards25519, () => publicKey);
   * let msg = Provable.witness(Provable.Array(Field, 9), () => messageBytes.map(Field));
   * let sig = Provable.witness(Eddsa, () => signature);
   *
   * // verify signature
   * let isValid = sig.verify(msg, pk);
   * isValid.assertTrue('signature verifies');
   * ```
   */
  verify(message: Bytes, publicKey: FlexiblePoint): Bool {
    let publicKey_ = this.Constructor.Curve.from(publicKey);
    return Eddsa.verify(
      toObject(this),
      message.bytes,
      encode(toPoint(publicKey_)),
    );
  }

  /**
   * Create an {@link EddsaSignature} by signing a message with a private key.
   *
   * Note: This method is not provable, and only takes JS bigints as input.
   */
  static sign(
    message: (bigint | number)[] | Uint8Array,
    privateKey: bigint,
  ): EddsaSignature {
    let { R, s } = Eddsa.sign(privateKey, message);
    return new this({ R, s });
  }

  /**
   * Check structural validity of the signature representation.
   *
   * This range-checks the foreign-field limbs of `R` and `s`, and proves that
   * `s` is almost reduced modulo the scalar field. It does not prove that `R`
   * decodes to a valid curve point or that the signature verifies; those checks
   * happen in {@link verify}.
   */
  static check(signature: EddsaSignature) {
    multiRangeCheck(signature.R.value);
    multiRangeCheck(signature.s.value);
    // more efficient than the automatic check, which would do this for each scalar separately
    this.Curve.Scalar.assertAlmostReduced(signature.s);
  }

  // dynamic subclassing infra
  get Constructor() {
    return this.constructor as typeof EddsaSignature;
  }
  static _Curve?: typeof ForeignTwisted;
  static _provable?: ProvablePureExtended<
    EddsaSignature,
    { R: bigint; s: bigint },
    { R: string; s: string }
  >;

  /**
   * The {@link ForeignTwisted} on which the EdDSA signature is defined.
   */
  static get Curve() {
    assert(this._Curve !== undefined, 'EddsaSignature not initialized');
    return this._Curve;
  }
  /**
   * `Provable<EddsaSignature>`
   */
  static get provable() {
    assert(this._provable !== undefined, 'EddsaSignature not initialized');
    return this._provable;
  }
}

/**
 * Create a class {@link EddsaSignature} for verifying EdDSA signatures on the given curve.
 */
function createEddsa(
  curve: TwistedCurveParams | typeof ForeignTwisted,
): typeof EddsaSignature {
  let Curve0: typeof ForeignTwisted =
    'd' in curve ? createForeignTwisted(curve) : curve;
  class Curve extends Curve0 {}

  // R is a compressed point encoding (up to 2^256) that must not be reduced
  // modulo the base field or scalar field. We create a provable for R that
  // converts bigints to Field3 (raw limbs) to bypass ForeignField's mod reduction.
  let baseProvable = Curve.Field.provable;
  let UnreducedR: typeof baseProvable = {
    ...baseProvable,
    fromValue(x: any) {
      if (typeof x === 'bigint' || typeof x === 'number' || typeof x === 'string') {
        return new Curve.Field(Gadgets.Field3.from(BigInt(x)));
      }
      return baseProvable.fromValue(x);
    },
  };

  class Signature extends EddsaSignature {
    static _Curve = Curve;
    static _provable = provableFromClass(Signature, {
      R: UnreducedR,
      s: Curve.Scalar,
    });
  }

  return Signature;
}

function toObject(signature: EddsaSignature) {
  return { R: signature.R.value, s: signature.s.value };
}
