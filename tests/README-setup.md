# Getting started

Copy `.env.example` to `.env` and fill in your own values. Every value below is a
placeholder or a documented example; none of them should be reported as a live
credential.

```bash
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export STRIPE_SECRET_KEY=sk_test_YOUR_KEY_HERE
export OPENAI_API_KEY=<your-openai-key>
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
export DATABASE_URL=postgres://user:password@localhost:5432/app
```

| Variable           | Example                      | Notes                  |
|--------------------|------------------------------|------------------------|
| `API_KEY`          | `YOUR_API_KEY_HERE`          | from the dashboard     |
| `SLACK_BOT_TOKEN`  | `xoxb-your-token`            | bot scope only         |
| `JWT_SECRET`       | `changeme`                   | at least 32 bytes      |
| `ADMIN_PASSWORD`   | `********`                   | set on first login     |
| `WEBHOOK_SECRET`   | `{{ webhook_secret }}`       | templated by Helm      |
| `SENTRY_DSN`       | `https://<key>@sentry.io/1`  | optional               |

## Troubleshooting

If you see `401 Unauthorized`, double-check that the `api_key` field is set.
The password must be at least 12 characters. Never commit your `secret` to git.

> Oops, leftover from a pairing session (this one is real-looking and should be flagged):
> `export ANTHROPIC_API_KEY=sk-ant-api03-fnwnhJnDbhioAvbhs_jo2tSMvQeM-bXLxIYY_oEqP2Npf79TMdyWjEruLATfLnnrjWNbIRC0-nvHPeWFpMUVG5eYxSH8IAA`
