# Shared Memory Schema

`shared_memory.json` 是多智能体协作状态；`paper_metadata.json` 是论文事实。

不要混用两者。

---

## File Responsibilities

| File | Purpose | Writer | Reader |
|---|---|---|---|
| `paper_metadata.json` | 论文静态事实（标题、章节、公式、图元数据） | Coordinator + Figure Analyst | All agents |
| `shared_memory.json` | 协作状态（概念归属、术语、评审、进度） | Coordinator + Chapter Agents + Editor-in-Chief | All agents |

---

## paper_metadata.json (Static)

```json
{
  "title": "Attention Is All You Need",
  "authors": ["..."],
  "year": 2017,
  "venue": "NeurIPS 2017",
  "pdf_source": "/path/to/paper.pdf",
  "chapters": [
    {"id": "ch1", "title": "Introduction", "page_range": "2-3"}
  ],
  "equations": [
    "Attention(Q, K, V) = softmax(QK^T / sqrt(d_k))V"
  ],
  "image_analysis": {
    "status": "available",
    "method": "read_tool_multimodal",
    "analyzed_at": "2026-02-25T10:00:00Z"
  },
  "figures": [
    {
      "file": "fig_3_0_xxx.png",
      "page": 4,
      "level1_summary": "...",
      "figure_type": "architecture_diagram",
      "key_elements": ["..."],
      "analyzed_by": "figure_analyst_agent",
      "analyzed_at": "2026-02-25T10:00:00Z",
      "analysis_method": "read_tool_multimodal",
      "status": "analyzed"
    }
  ]
}
```

---

## shared_memory.json (Dynamic)

```json
{
  "chapter_summaries": [
    {
      "chapter_id": "ch1",
      "title": "Introduction",
      "summary": "200-500 word summary",
      "assigned_agent": "agent_1",
      "word_count_target": 700,
      "status": "pending",
      "review_score": null,
      "reviewer": null,
      "review_comments": null
    }
  ],
  "terminology_registry": {
    "Self-Attention": {
      "definition": "...",
      "defined_by": "agent_1",
      "chapter_id": "ch3"
    }
  },
  "concept_coverage_map": {
    "scaled dot-product attention": {
      "owner": "agent_1",
      "chapter_id": "ch3"
    }
  },
  "communication": {
    "broadcast": [
      {
        "from": "coordinator",
        "message": "Use figure summaries only; do not invent figure content.",
        "timestamp": "2026-02-25T10:00:00Z"
      }
    ],
    "directed": [
      {
        "from": "agent_1",
        "to": "agent_2",
        "message": "Please reuse shared term for cross-attention.",
        "timestamp": "2026-02-25T10:05:00Z"
      }
    ]
  },
  "external_resources": [
    {
      "title": "The Annotated Transformer",
      "url": "https://nlp.seas.harvard.edu/2018/04/03/attention.html",
      "type": "tutorial"
    }
  ],
  "progress": {
    "coordinator": "completed",
    "figure_analyst": "completed",
    "agent_1": "pending_review",
    "editor_in_chief": "in_progress"
  }
}
```

---

## Review Status Contract

`chapter_summaries[i].status` 仅允许：
- `pending`
- `pending_review`
- `needs_revision`
- `approved`

通过评审时必须同时满足：
- `status = "approved"`
- `review_score >= 4.0`
- `reviewer = "editor_in_chief"`

---

## Chapter ID Contract

- `paper_metadata.json.chapters[].id` 与 `shared_memory.json.chapter_summaries[].chapter_id` 必须一一对应
- 推荐格式：`ch1`, `ch2`, ...
- `chapters/chapter_{XX}_output.md` 需要和 chapter id 顺序一致（`ch1 -> chapter_01_output.md`）

---

## Update Patterns

### Register concept ownership

```json
{
  "concept_coverage_map": {
    "Multi-Head Attention": {
      "owner": "agent_2",
      "chapter_id": "ch3"
    }
  }
}
```

### Register terminology

```json
{
  "terminology_registry": {
    "d_model": {
      "definition": "Model hidden size",
      "defined_by": "agent_2",
      "chapter_id": "ch2"
    }
  }
}
```

### Mark chapter for review

```json
{
  "chapter_summaries": [
    {
      "chapter_id": "ch3",
      "status": "pending_review"
    }
  ]
}
```

---

## What Must Not Go Into shared_memory.json

- 原始 PDF 内容全文
- 图像二进制内容
- 与章节无关的长篇笔记

这些内容会导致上下文污染，降低多智能体一致性。
