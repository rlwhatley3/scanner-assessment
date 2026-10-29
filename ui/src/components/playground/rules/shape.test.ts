import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { describeRule } from "./describe.ts";
import { LABEL_PATTERN, NEW_PREFIX_SHAPE, type Shape, shapeFields, shapeOf } from "./shape.ts";

function roundTrip(shape: Shape): Shape {
  const fields = shapeFields(shape);
  assert.ok(fields);
  return shapeOf(fields);
}

describe("shapeFields", () => {
  it("writes a prefix shape as a value group with a boundary after it", () => {
    const fields = shapeFields({
      kind: "prefix",
      prefix: "acme_",
      length: "24",
      charset: "alphanumeric",
    });
    assert.equal(fields?.pattern, "\\b(?P<value>acme_[A-Za-z0-9]{24})(?:[^A-Za-z0-9]|$)");
    assert.equal(fields?.prefix, "acme_");
    assert.equal(fields?.detectionType, "direct_credential");
  });

  it("escapes regex characters in the prefix and skips \\b before punctuation", () => {
    const fields = shapeFields({ kind: "prefix", prefix: "$tok.", length: "8", charset: "hex" });
    assert.equal(fields?.pattern, "(?P<value>\\$tok\\.[0-9a-fA-F]{8})(?:[^0-9a-fA-F]|$)");
  });

  it("writes a label shape as the assignment pattern plus key names", () => {
    const fields = shapeFields({ kind: "label", labels: "password, token" });
    assert.equal(fields?.pattern, LABEL_PATTERN);
    assert.equal(fields?.keyNames, "password, token");
    assert.equal(fields?.detectionType, "likely_credential");
  });

  it("leaves custom rules alone", () => {
    assert.equal(shapeFields({ kind: "custom" }), null);
  });
});

describe("shapeOf", () => {
  it("reads back what shapeFields writes", () => {
    const shapes: Shape[] = [
      { kind: "prefix", prefix: "acme_", length: "24", charset: "alphanumeric" },
      { kind: "prefix", prefix: "$tok.", length: "8", charset: "hex" },
      { kind: "prefix", prefix: "sk-", length: "40", charset: "token" },
      { kind: "label", labels: "password" },
    ];
    for (const shape of shapes) assert.deepEqual(roundTrip(shape), shape);
  });

  it("starts a rule with no pattern as a prefix shape", () => {
    assert.deepEqual(shapeOf({ pattern: "", keyNames: "", detectionType: "" }), NEW_PREFIX_SHAPE);
  });

  it("treats hand-written patterns as custom", () => {
    for (const pattern of ["\\bAKIA[0-9A-Z]{16}\\b", "(?P<value>a+[0-9]{4})(?:[^0-9]|$)"]) {
      assert.deepEqual(shapeOf({ pattern, keyNames: "", detectionType: "direct_credential" }), {
        kind: "custom",
      });
    }
  });
});

describe("describeRule", () => {
  it("describes simple-editor rules from their shape", () => {
    const prefix = shapeFields({
      kind: "prefix",
      prefix: "acme_",
      length: "24",
      charset: "alphanumeric",
    });
    assert.equal(
      describeRule({ ...prefix, keyNames: [] }),
      "Text starting with “acme_”, then 24 letters and numbers.",
    );
    assert.equal(
      describeRule({
        pattern: LABEL_PATTERN,
        keyNames: ["password", "token"],
        detectionType: "likely_credential",
      }),
      "Values after labels like password, token.",
    );
  });

  it("falls back to the rule type for hand-written rules", () => {
    assert.equal(
      describeRule({
        pattern: "\\bAKIA[0-9A-Z]{16}\\b",
        prefix: "AKIA",
        detectionType: "direct_credential",
      }),
      "A specific key or token format, starting with “AKIA”.",
    );
    assert.equal(describeRule({}), "Not finished yet.");
  });
});

describe("describeRule label lists", () => {
  it("names the first three labels and counts the rest", () => {
    assert.equal(
      describeRule({
        pattern: LABEL_PATTERN,
        keyNames: ["password", "secret", "token", "api_key", "passphrase"],
        detectionType: "likely_credential",
      }),
      "Values after labels like password, secret, token and 2 more.",
    );
  });
});
