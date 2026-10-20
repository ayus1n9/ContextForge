# Amazon Bedrock and Bedrock Guardrails Setup Guide

AegisRAG supports optional integration with **Amazon Bedrock** foundation models (such as Claude 3.5 Sonnet) and **Amazon Bedrock Guardrails**.

> [!NOTE]
> Amazon Bedrock is **strictly optional**. The application runs 100% locally with zero cloud dependencies using the default deterministic mock provider. No AWS credentials are required for local development or automated testing.

---

## 1. Prerequisites

1. An active AWS account with Amazon Bedrock model access granted in your target region (e.g., `us-east-1` or `us-west-2`).
2. IAM credentials configured via standard AWS mechanisms (`~/.aws/credentials`, environment variables, or IAM Instance Profile / ECS Task Role).
3. Python package `boto3` installed (included in AegisRAG dependencies).

---

## 2. Environment Configuration

To enable Amazon Bedrock, set the following environment variables in your `.env` file:

```env
# Enable Bedrock as the LLM provider
LLM_PROVIDER=bedrock

# AWS Target Region
AWS_REGION=us-east-1

# Foundation Model Identifier
BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0

# Optional Embedding Model
EMBEDDING_PROVIDER=bedrock
BEDROCK_EMBEDDING_MODEL_ID=amazon.titan-embed-text-v2:0

# Optional Amazon Bedrock Guardrail Configuration
BEDROCK_GUARDRAIL_ID=your-guardrail-id
BEDROCK_GUARDRAIL_VERSION=DRAFT
```

---

## 3. Least-Privilege IAM Policy

Attach the following policy to your application IAM role or user:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BedrockModelInvocation",
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:Converse"
      ],
      "Resource": [
        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-5-sonnet-20241022-v2:0",
        "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-embed-text-v2:0"
      ]
    },
    {
      "Sid": "BedrockGuardrailsEvaluation",
      "Effect": "Allow",
      "Action": [
        "bedrock:ApplyGuardrail"
      ],
      "Resource": [
        "arn:aws:bedrock:us-east-1:*:guardrail/*"
      ]
    }
  ]
}
```

---

## 4. Cost and Token Controls

AegisRAG implements application-side cost protection controls:
- **Max Input Length**: Queries capped at 2,000 characters before reaching Bedrock.
- **Max Tokens**: Bedrock generation calls are hard-capped at 1,024 output tokens.
- **Bounded Retries**: Maximum of 2 retries with exponential backoff on service errors.
- **Zero Ingestion Leakage**: PDF documents are NOT uploaded to Bedrock during ingestion. Only retrieved context chunks for authorized user queries are transmitted during chat queries.
