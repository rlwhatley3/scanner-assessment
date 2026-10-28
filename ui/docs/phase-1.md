Before implementation, explore the problem space and think through the user needs. Come prepared to walk through:

1. Who is the user, and what are they trying to accomplish?
2. What should happen from the moment they enter text through reviewing and acting on a finding?
3. What are the main frontend, API, and detection-engine boundaries?
4. What should a finding contain? How should it be represented in the source text?
5. What assumptions are you making about rules, configuration errors, and scan results?
6. What would you build first, and what would you deliberately leave out?

Sketch the main flow and a high-level system design. This phase is about discovery and communication; you do not need to produce a polished design document.

Use [**Whiteboard**](/whiteboard) to sketch your findings. It starts with four user scenarios to design: scanning a source file, triaging an example value, configuring a detection rule, and reviewing zero or overlapping results. Add your own user flows, system boundaries, assumptions, and open questions. Your board auto-saves under `whiteboard/` at the repository root; include the saved file with your presentation if useful.
