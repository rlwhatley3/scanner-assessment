// Sample inputs from the repo's tests/ folder. Every credential in them is fake.
import accessLog from "../../../../../tests/access.log?raw";
import appEnv from "../../../../../tests/app.env?raw";
import cleanLookalikes from "../../../../../tests/clean-lookalikes.yaml?raw";
import mainTf from "../../../../../tests/main.tf?raw";
import paymentClient from "../../../../../tests/payment_client.py?raw";

export const SAMPLES = [
  { label: ".env file", text: appEnv },
  { label: "Terraform config", text: mainTf },
  { label: "Python source", text: paymentClient },
  { label: "Application log", text: accessLog },
  { label: "Clean YAML (no secrets)", text: cleanLookalikes },
];
