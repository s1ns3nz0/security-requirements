# AI threat taxonomy

## When this applies, and when it must not

Only when the architecture declares or the repository shows an LLM, agent, RAG,
vector store, embedding pipeline, or model endpoint.

**With no such component, this taxonomy is not applied and not mentioned.** Not
"applied and found empty", not "AI threats: none applicable" — absent. A review
that prints a section saying nothing happened teaches the reader that sections
in this document can be skipped, and the next one they skip is one that
mattered. Silence about an inapplicable category is the correct disclosure.

The detection rule is deliberately narrow. A component *named* for a model
(`llm-gateway`, `rag-indexer`, `bedrock-proxy`) is one; a billing service whose
description happens to mention AI is not. A false positive here does not just
add noise — it produces threat categories nobody can act on, and a reviewer who
has dismissed this section once will dismiss it on the service where it was
real.

## What makes these different from the STRIDE pass

The ordinary threat model already covers the deployment: the model endpoint is a
network service, its credentials are credentials, its logs are logs. Do not
restate those here. What follows are the failures that exist *because* the
system routes untrusted text into something that acts on it.

The distinction that organises all of them: **an LLM cannot separate
instructions from data.** Every category below is a consequence of that, and any
control that assumes it can is not a control.

## Categories

### AI-01 Prompt injection

Untrusted content reaching the model as instruction. The classic case is a
retrieved document or a user field, but the ones that ship are indirect: a
README, a filename, an HTML comment, a calendar invite, a commit message.

Ask what the model *reads*, not what the user *types*. If any of it comes from
somewhere the operator does not control, this applies.

The mitigation is never "sanitise the input" — there is no grammar to sanitise
against. It is to bound what the model can *do* with an instruction it obeys:
least privilege on its tools, confirmation on side effects, and never granting
it an authority the requester lacked.

### AI-02 Excessive agency

The model can take an action whose blast radius exceeds what the requesting user
was authorised to do. An agent with a database credential is not "an agent" —
it is the credential, reachable by anyone who can phrase a request.

Score this against the *tool*, not the model. The question is what the worst
call in the tool list does, executed on behalf of the least trusted caller.

### AI-03 Training and context data disclosure

Sensitive data reaching a model that logs, retains, or trains on it — including
a provider's retention window, a prompt cache, or a trace in an observability
tool. This is a disclosure boundary like any other and belongs on the DFD: draw
the flow to the provider and mark what crosses it.

### AI-04 Retrieval poisoning

Whoever can write to the corpus can steer the answer. Ask who can add a
document, whether that path has the same authorisation as the answer it
influences, and whether a retrieved chunk is distinguishable from a system
instruction at the point of assembly.

### AI-05 Output handled as trusted

Model output reaching a sink that executes it: a shell, an SQL string, a
template, `eval`, a browser as unescaped HTML, or another agent as instruction.
This is the injection you already know, with a generator that is *supposed* to
produce plausible text.

Treat model output exactly as user input on the way out.

### AI-06 Unbounded consumption

Token cost, context growth, and tool-call loops are a denial-of-wallet surface
before they are a denial-of-service one. Cap turns, cap spend, and make the cap
observable to somebody who can act on it.

### AI-07 Supply chain of models and prompts

A model version, a system prompt, and a tool definition are all deployed
artifacts that change behaviour. If they can change without review, the review
this document belongs to describes a system that no longer exists.

## Recording a finding

Use the ordinary threat record. These are threats, not a separate document:
`category` carries the AI id alongside its STRIDE letter where one fits, and
`boundary` names the flow that carries the untrusted text. A finding here is
scored by the same engine and against the same appetite as any other.

If the taxonomy raises a category no modelled threat addresses, that is a gap in
the threat model — report it as an uncovered category rather than inventing a
threat record to fill it. The model belongs to whoever ran the interview.
