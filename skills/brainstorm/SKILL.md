---
name: brainstorm
description: >
  Launch multiple parallel sub-agents to brainstorm ideas, solutions, or approaches for any topic.
  Use when users request creative thinking, diverse perspectives, idea generation, problem-solving,
  or exploration of multiple approaches. This skill generates diverse OPTIONS (not verified conclusions)
  through parallel agent exploration. Supports configurable number of sub-agents (default: 3), adapts
  prompt strategy based on context, and encourages sub-agents to leverage web search for research-backed
  insights. For evidence-based investigation and authoritative synthesis, use the research skill instead.

allowed-tools:
  # MCP Search and Fetch Tools (Required for web research during brainstorming)
  - mcp__brave-search__brave_web_search
  - mcp__brave-search__brave_news_search
  - mcp__brave-search__brave_video_search
  - mcp__brave-search__brave_image_search
  - mcp__brave-search__brave_local_search
  - mcp__brave-search__brave_summarizer
  - mcp__fetch__fetch
  - mcp__web_reader__webReader

  # Core tools for brainstorm workflow
  - AskUserQuestion
  - Task
  - Read
  - Write
  - Edit
  - Glob
  - Grep
  - Bash
---

# Brainstorm

Launch parallel sub-agents to generate diverse ideas and perspectives, then synthesize results.

## Workflow

### 1. Determine Agent Count

**Default: 3 agents**

Adjust based on task complexity:
- **Simple questions**: 2-3 agents
- **Moderate complexity**: 3-5 agents
- **Complex/strategic**: 5-7 agents
- **Research-heavy**: 4-6 agents

More agents = more diversity but longer runtime and synthesis effort.

### 2. Adapt Prompt Strategy

Tailor the brainstorm prompt based on context:

**For technical problems:**
```
"Generate 3-5 distinct technical approaches to solve [PROBLEM]. Consider:
- Different architectural patterns
- Trade-offs (performance, complexity, maintainability)
- Edge cases and failure modes
Use mcp__brave-search__brave_web_search to research current best practices and validate your approaches.
Be specific and actionable."
```

**For creative tasks:**
```
"Generate 5-7 creative ideas for [TOPIC]. Focus on:
- Originality and novelty
- Practicality where relevant
- Diverse perspectives and angles
Think expansively."
```

**For strategic decisions:**
```
"Analyze [SITUATION] from multiple angles. Consider:
- Strategic implications
- Risks and opportunities
- Short-term vs long-term trade-offs
Use mcp__brave-search__brave_web_search to research similar case studies and industry benchmarks.
Provide reasoned recommendations with supporting evidence."
```

**General/open-ended:**
```
"Brainstorm ideas for [TOPIC]. Provide diverse, thoughtful perspectives."
```

### 3. Launch Sub-Agents

Use Task tool to launch all sub-agents in a single message (parallel execution):

```python
Task(subagent_type="general-purpose", prompt="[ADAPTED_PROMPT]", description="Brainstorm approach 1")
Task(subagent_type="general-purpose", prompt="[ADAPTED_PROMPT]", description="Brainstorm approach 2")
Task(subagent_type="general-purpose", prompt="[ADAPTED_PROMPT]", description="Brainstorm approach 3")
```

**Important:**
- Use `general-purpose` subagent_type for flexibility
- All agents receive identical prompt instructions
- Launch in parallel for efficiency
- Use short, clear descriptions (3-5 words)
- **Sub-agents have full tool access** including WebSearch, file operations
- **Code execution**: Sub-agents should propose code/scripts for you (main agent) to execute
- **Encourage tool use**: When prompts benefit from current information, explicitly invite web research:
  - "Use mcp__brave-search__brave_web_search to find recent examples and best practices"
  - "Research current industry approaches before suggesting solutions"
  - "Include web sources to support your recommendations"
  - "Propose code snippets or scripts that I can execute to validate your ideas"

### 4. Analyze Results

Wait for all agents to complete, then:

**Identify themes:**
- Group similar ideas together
- Note unique perspectives from each agent
- Highlight contradictions or complementary approaches

**Evaluate quality:**
- Flag most actionable/practical ideas
- Note creative or innovative solutions
- Identify potential risks or concerns

**Synthesize:**
- Organize by theme or category
- Preserve diversity of thought
- Highlight consensus vs disagreement
- Provide clear next steps if applicable
- **Execute proposed code** if agents provided validation scripts that would help confirm ideas

### 5. Present Summary

Structure output for readability:

```markdown
## Synthesis

[2-3 sentence overview of key patterns]

## Themes

### Theme 1
[Idea group summary]
- Key point 1
- Key point 2

### Theme 2
[Idea group summary]
- Key point 1

## Notable Ideas

[Standout insights that don't fit major themes]

## Recommendations

[If applicable: prioritized suggestions or next steps]
```

## Tips

**When to adjust agent count up:**
- Highly complex problems
- Need for exhaustive exploration
- Strategic decisions with high stakes

**When to adjust agent count down:**
- Quick, simple questions
- Tight time constraints
- Narrow, well-defined problems

**Effective prompts:**
- Be specific about what you want
- Encourage diversity of thinking
- Set appropriate constraints (e.g., "3-5 ideas")
- Match prompt style to domain (technical vs creative)

**Synthesis quality:**
- Don't just list everything—group and prioritize
- Call out patterns and disagreements
- Preserve the best ideas from each agent

**When to encourage tool use in prompts:**
- **Web search**: Current best practices, recent technologies, market trends, competitive analysis
- **Code proposals**: Ask sub-agents to propose code/scripts for main agent to execute
- **File operations**: Analyze existing codebases, reference documentation, review examples
- **Research needs**: When brainstorming about fast-moving domains (AI, web frameworks, security)

**Recommended MCP tools for web research:**
- **mcp__brave-search__brave_web_search**: General web searches for examples and best practices
- **mcp__brave-search__brave_news_search**: Recent news and market trends
- **mcp__fetch__fetch**: Fetch specific URLs for detailed analysis
- **mcp__web_reader__webReader**: Extract content from web pages in markdown format

## When to Transition to Research

After brainstorming completes, consider transitioning to the research skill if:

- **User needs validation**: "Are these approaches actually viable?" or "What's the best practice?"
- **Evidence required**: Decision-making requires authoritative sources, not just creative options
- **Technical verification**: Ideas need validation against documentation, benchmarks, or case studies
- **User request shifts**: User asks "research this," "what does literature say," "find authoritative sources"
- **High-stakes decisions**: Security, architecture, or technology selection requires evidence backing

**Suggest research explicitly:**
> "I've generated diverse options for [TOPIC]. Would you like me to research any of these approaches to validate them against best practices and authoritative sources?"

**Integration patterns:**
- **Brainstorm → Research**: Generate options, then validate top choices
- **Research → Brainstorm**: Learn best practices first, then generate creative applications
- **Iterative**: Alternate between both for comprehensive problem-solving

## Tool Usage Strategy

### Main Agent Tools
- **Task tool** (primary): Launch parallel sub-agents
- **Bash** (optional): Execute validation scripts proposed by sub-agents
- **Write/Edit**: Format synthesis output

### Sub-Agent Tools (Parallel, Independent)
- **mcp__brave-search__brave_web_search** (encouraged): Find current examples, best practices, competitive analysis
- **Read/Grep/Glob** (as needed): Explore existing codebase if relevant to brainstorm
- **Code proposals**: Suggest scripts for main agent to execute (don't run directly)

### Tool Emphasis
- **Diversity over depth**: Each agent explores different angles independently
- **Speed over thoroughness**: Quick searches to inform creative thinking
- **Examples over rigor**: Find representative examples, not comprehensive coverage
- **Parallel exploration**: No agent sees another's output until synthesis phase
