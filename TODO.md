# TODO: Improve Response Quality and Agent Behavior

## 1. Prevent Empty/Zero-Length LLM Responses
- [x] Add minimal retry guard in `openrouter_engine.py` generate_response method
- [x] If response is empty or zero-length, retry the LLM call once before falling back

## 2. Improve Persona Consistency
- [x] Modify orchestrator to include turn_count in metadata dict
- [x] Update _build_system_prompt in openrouter_engine.py to use turn_count for stage-appropriate instructions
- [x] Select persona and stage instructions based on turn_count (early: curiosity, middle: engagement, late: deep extraction)

## 3. Increase Engagement by One Extra Turn
- [x] Update system prompt to encourage asking one more clarification question to extend conversation naturally
- [x] Add prompt instruction to sustain engagement without changing exit logic
