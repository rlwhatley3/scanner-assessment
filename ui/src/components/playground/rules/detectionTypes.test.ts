import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { Model } from "../api.ts";
import { offersDetectionType } from "./detectionTypes.ts";

const SHIPPED: Model[] = [
  { id: "secret-detector", sha256: "c8".repeat(32), inputLength: 256, uses: ["model_detection"] },
  { id: "value-classifier", sha256: "69".repeat(32), inputLength: 128, uses: ["value_classifier"] },
];

describe("offersDetectionType", () => {
  it("hides a model rule type no loaded model fits", () => {
    assert.equal(offersDetectionType("model_assessment", SHIPPED, ""), false);
    assert.equal(offersDetectionType("model_detection", SHIPPED, ""), true);
  });

  it("keeps the rule's own type", () => {
    assert.equal(offersDetectionType("model_assessment", SHIPPED, "model_assessment"), true);
  });

  it("offers every type until the models are known", () => {
    assert.equal(offersDetectionType("model_assessment", null, ""), true);
  });

  it("always offers pattern rule types", () => {
    assert.equal(offersDetectionType("likely_credential", [], ""), true);
  });
});
