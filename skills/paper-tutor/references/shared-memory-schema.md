# Shared Memory Schema

Complete schema for the shared working memory that all agents access.

## Overview

The shared working memory is NOT a single file that gets loaded into context. Instead, it's a **conceptual structure** that agents interact with through:

1. **Reading/Writing a JSON file** (`shared_memory.json`)
2. **Sending messages** (broadcast or directed)
3. **Checking state** before taking action

Each agent only loads relevant portions into their context.

---

## Complete Schema

```yaml
shared_memory:

  # ===== PAPER CONTENT =====
  # 重要：章节全文不存储在共享内存中
  # - 每个智能体只读取自己负责的章节全文（从原始论文文件）
  # - 其他智能体只能看到章节摘要（200-500字）
  # - 这样可以节省约 66% 的 context 使用
  paper:
    # 元信息（所有智能体可见）
    metadata:
      title: "论文标题"
      authors: ["作者1", "作者2"]
      year: 2026
      venue: "会议/期刊名称"
      arxiv_id: "arXiv:XXXX.XXXXX"
      pdf_source: "URL or local path"
      original_file_path: "/path/to/paper.pdf"  # 原始文件位置

    # 章节摘要（所有智能体可见）
    # 每个章节的 200-500 字摘要
    # 智能体通过摘要了解其他章节，不加载全文
    chapter_summaries:
      - chapter_id: "ch1"
        title: "Introduction"
        summary: "200-500字的摘要..."
        assigned_agent: "Agent_1"
        word_count_target: 5000  # 根据强度计算
        # 注意：章节全文不在共享内存中
        # Agent_1 会从 original_file_path 读取

      - chapter_id: "ch2"
        title: "Method"
        summary: "200-500字的摘要..."
        assigned_agent: "Agent_2"
        word_count_target: 8000

    # 跨章节引用索引（所有智能体可见）
    cross_references:
      - type: "concept"
        name: "Transformer"
        appears_in: ["ch1", "ch2", "ch4"]
        primary_location: "ch2"
        explained_by: "Agent_2"

      - type: "equation"
        identifier: "公式2.3"
        cited_in: ["ch3", "ch4"]
        explained_in: "ch2"

      - type: "figure"
        identifier: "fig_001"
        cited_in: ["ch4", "ch5"]
        original_caption: "The Transformer architecture"

  # ===== 图表索引（渐次披露） =====
  # 核心思想：原图存储在 figures/ 目录，共享内存存储元信息
  # 优化：
  # - 跳过太小的图（< 100x100 或面积 < 10000）
  # - 使用哈希去重（感知哈希 + MD5）
  # - 不处理图像（移除 processed_file）
  # - 被过滤的小图不存储
  # - 多键查找（位置、编号、哈希）
  figures_index:

    # ===== 查找索引（多键） =====
    lookup:
      # 按位置查找（主要方式）
      # key: "page_number-original_figure_number"
      by_location:
        "p3-Figure 1": "fig_001"
        "p3-Figure 2": "fig_002"
        "p5-Table 1": "table_001"

      # 按原文编号查找
      by_original_number:
        "Figure 1": "fig_001"
        "Figure 2": "fig_002"
        "Table 1": "table_001"
        # 变体
        "Fig. 1": "fig_001"
        "Fig.1": "fig_001"

      # 按哈希查找（去重检测）
      by_hash:
        "1a2b3c4d5e6f7g8h": "fig_001"
        "9z8y7x6w5v4u3t2s": "fig_002"

    # ===== 图片数据 =====
    figures:
      - figure_id: "fig_001"
        # ===== 所有的原始位置（去重时合并） =====
        # 一个图可能在多个地方被引用
        locations:
          - page: 3
            chapter: "ch3"
            section: "3.1"
            original_number: "Figure 1"
            caption: "The Transformer architecture"
            position_in_page: "top"  # top | middle | bottom
            is_reference: false  # 首次出现

          # 如果在其他地方重复引用
          - page: 7
            chapter: "ch4"
            section: "4.2"
            original_number: "Figure 1"
            caption: "The Transformer architecture (repeated)"
            position_in_page: "middle"
            is_reference: true  # 标记为引用

        # 基本信息
        type: "architecture_diagram"  # architecture_diagram | flowchart | experimental_results | data_plot | photograph | formula_derivation | comparison_table | etc.

        # 是否可以用 Mermaid 重现
        mermaid_reproducible: false

        # Mermaid 版本（如果可重现）
        mermaid_version: null

        # 渐次披露：文件引用
        original_file: "@figures/fig_001_transformer_architecture.png"

        # ===== 图片哈希（去重用） =====
        image_hash:
          perceptual: "a3f5b8c2d1e4f6g7"  # 感知哈希，用于检测相似图片
          md5: "1a2b3c4d5e6f7g8h"  # MD5，用于精确去重

        # ===== 图片尺寸信息 =====
        dimensions:
          width: 1200
          height: 800
          area: 960000
          is_too_small: false
          filter_reason: null

        # ===== 多模态理解结果 =====
        # 按需理解，不预先存储
        multimodal_understanding: null

        # 首次出现的位置（主要位置）
        primary_location:
          page: 3
          chapter: "ch3"
          section: "3.1"

        # 图表内容摘要（用于智能体快速理解）
        content_summary: |
          这个图展示了 Transformer 的整体架构：
          - 左侧是 Encoder，右侧是 Decoder
          - Encoder 由 N 个相同的层堆叠而成

        # 图表的关键元素
        key_elements:
          - "Encoder 堆叠"
          - "Decoder 堆叠"
          - "Multi-Head Attention"

        # 相关概念
        related_concepts: ["Transformer架构", "Encoder", "Decoder"]

        # 相关公式
        related_equations: ["公式3.1", "公式3.2"]

        # 引用此图的其他章节
        cited_in: ["ch4", "ch5"]

        # 讲解提示
        teaching_tips:
          reading_order: "从左到右，从上到下"
          key_focus: "注意 Encoder 和 Decoder 的连接"
          common_misunderstanding: "容易忽略 Add & Norm 层"

  # ===== 术语表（含挑战机制） =====
  terminology:

    terms:
      - term_id: "term_001"
        term: "注意力机制"
        english: "Attention Mechanism"
        definition: "..."

        # 定义来源
        defined_by: "Agent_2"
        defined_in_chapter: "ch2"
        defined_at: "2026-02-22T10:30:00Z"

        # 状态: active | challenged | deprecated
        status: "active"

        # 挑战记录
        challenges: []

        # 仲裁结果（如果有）
        arbitration: null

      - term_id: "term_002"
        term: "自注意力"
        english: "Self-Attention"
        definition: "..."
        defined_by: "Agent_2"
        defined_in_chapter: "ch2"
        status: "challenged"

        challenges:
          - challenge_id: "chal_001"
            challenger: "Agent_3"
            chapter: "ch3"
            reason: "在实验章节的上下文中，表现形式不同..."
            alternative_definition: "..."
            timestamp: "2026-02-22T11:15:00Z"

        arbitration:
          arbitrator: "Editor-in-Chief"
          decision: "merge"
          reasoning: "两个定义都有效，合并为通用定义和特定应用场景"
          new_definition: "..."
          timestamp: "2026-02-22T11:30:00Z"

  # ===== 概念覆盖地图 =====
  concept_coverage:

    concepts:
      - concept_id: "concept_001"
        name: "Transformer架构"
        status: "completed"  # planned | in_progress | completed | contested

        # 计划讲解者
        planned_explainer: "Agent_2"

        # 实际讲解者
        actual_explainer: "Agent_2"

        # 位置
        location:
          chapter: "ch2"
          section: "2.3"

        # 字数
        word_count: 3500

        # 外部资源
        external_resources: ["res_001", "res_003"]

      - concept_id: "concept_002"
        name: "位置编码"
        status: "contested"

        # 竞争者
        contested_by:
          - agent: "Agent_2"
            chapter: "ch2"
            reasoning: "这是方法的核心部分"

          - agent: "Agent_3"
            chapter: "ch3"
            reasoning: "实验中使用了变体"

        # 仲裁状态
        arbitration: "pending"

  # ===== 通信日志（分层） =====
  communication:

    # 广播频道（所有人可见）
    broadcast:
      - message_id: "msg_001"
        sender: "Agent_2"
        timestamp: "2026-02-22T10:45:00Z"
        type: "external_resource"
        content: "发现一个很好的注意力机制教程: [链接]"
        importance: "high"

      - message_id: "msg_002"
        sender: "Editor-in-Chief"
        timestamp: "2026-02-22T11:30:00Z"
        type: "arbitration_result"
        content: "术语'注意力机制'定义已更新，请查阅"
        affected_chapters: ["ch2", "ch3"]

    # 定向消息（只有相关方可见）
    directed:
      - message_id: "msg_003"
        sender: "Agent_3"
        recipients: ["Agent_2", "Editor-in-Chief"]
        timestamp: "2026-02-22T11:00:00Z"
        type: "concept_negotiation"
        subject: "概念X的归属"
        content: "我认为概念X在我这里讲解更合适，因为..."
        status: "resolved"

      - message_id: "msg_004"
        sender: "Coordinator"
        recipients: ["Agent_1"]
        timestamp: "2026-02-22T10:00:00Z"
        type: "task_assignment"
        content: "你负责第1章"
        status: "acknowledged"

  # ===== 外部资源库（渐次披露） =====
  # 核心思想：共享内存存储摘要 + 文件引用，完整内容按需读取
  external_resources:

    resources:
      - resource_id: "res_001"
        type: "tutorial"
        title: "Attention Is All You Need 详细解释"
        url: "https://example.com/attention-tutorial"

        # 元信息（轻量级，存储在共享内存）
        contributor: "Agent_2"
        chapter: "ch2"
        related_concepts: ["注意力机制", "Transformer"]

        # 关键内容摘要（智能体可以用这个快速判断是否需要）
        summary: |
          这篇文章用通俗语言解释了注意力机制。核心观点：
          1. 注意力机制的本质是加权求和
          2. Q、K、V 的物理意义是查询、键、值
          3. 多头注意力类似于多个观察角度

        # 关键段落（可以直接引用，无需读取完整文件）
        key_quotes:
          - "想象你在读一本书，注意力机制就像你的眼睛会更多地关注某些关键词"
          - "Q、K、V 可以类比于数据库查询系统"

        # ===== 渐次披露：文件引用 =====
        # 如果智能体需要完整内容，读取这个文件
        # 格式：@external_resources/[chapter]/resource_id_title.md
        cached_file: "@external_resources/chapter_02/res_001_attention_tutorial.md"

        # 完整内容是否已缓存到文件
        has_cached_content: true

        # 推荐用于哪个强度
        recommended_for: ["light", "medium", "heavy"]

        # 质量评估
        quality:
          clarity: 5
          depth: 4
          accuracy: 5

      - resource_id: "res_002"
        type: "video"
        title: "Transformer 可视化讲解"
        url: "https://youtube.com/watch?v=xxx"

        # 元信息
        contributor: "Agent_1"
        chapter: "ch1"
        related_concepts: ["Transformer架构"]

        # 摘要
        summary: |
          这个视频用动画展示了 Transformer 的工作原理：
          1. 可视化了 Q、K、V 的计算过程
          2. 展示了多头注意力的并行计算
          3. 演示了位置编码的作用

        # 视频关键时间点（可以引用）
        key_timestamps:
          - timestamp: "02:15"
            description: "Q、K、V 可视化解释"
          - timestamp: "08:30"
            description: "多头注意力并行计算演示"

        # 渐次披露：视频没有缓存内容，只有原链接
        cached_file: null
        has_cached_content: false

        recommended_for: ["medium", "heavy"]

  # ===== 进度跟踪 =====
  progress:

    overall:
      total_chapters: 6
      completed_chapters: 3
      overall_percentage: 50

    chapters:
      - chapter_id: "ch1"
        assigned_agent: "Agent_1"
        status: "completed"
        word_count: 4800
        target_word_count: 5000
        start_time: "2026-02-22T10:00:00Z"
        end_time: "2026-02-22T10:45:00Z"

      - chapter_id: "ch2"
        assigned_agent: "Agent_2"
        status: "in_progress"
        word_count: 3500
        target_word_count: 8000
        start_time: "2026-02-22T10:00:00Z"
        estimated_completion: "2026-02-22T11:30:00Z"

    arbitration_queue:
      - pending: 2
      - completed: 5
```

---

## Access Patterns

### Agent 读取共享内存时

```python
# 伪代码
def read_shared_memory(agent_name, chapter_id):
    memory = load_json("shared_memory.json")

    # 1. 读取元信息
    metadata = memory["paper"]["metadata"]

    # 2. 读取所有章节摘要（了解全局）
    summaries = memory["paper"]["chapter_summaries"]

    # 3. 读取自己负责的章节（从原始论文文件）
    my_chapter = load_chapter_from_paper(chapter_id)

    # 4. 读取术语表
    terms = memory["terminology"]["terms"]

    # 5. 读取概念覆盖
    concepts = memory["concept_coverage"]["concepts"]

    # 6. 读取广播消息
    broadcast = memory["communication"]["broadcast"]

    # 7. 只读取发给自己的定向消息
    directed = [
        msg for msg in memory["communication"]["directed"]
        if agent_name in msg["recipients"]
    ]

    return {
        "metadata": metadata,
        "summaries": summaries,
        "my_chapter": my_chapter,
        "terms": terms,
        "concepts": concepts,
        "broadcast": broadcast,
        "directed": directed
    }
```

### Agent 更新共享内存时

```python
# 伪代码
def update_shared_memory(agent_name, updates):
    memory = load_json("shared_memory.json")

    # 根据更新类型处理
    if updates["type"] == "register_concept":
        # 注册概念
        memory["concept_coverage"]["concepts"].append({
            "concept_id": generate_id(),
            "name": updates["name"],
            "status": "in_progress",
            "planned_explainer": agent_name,
            "location": updates["location"]
        })

    elif updates["type"] == "define_term":
        # 定义术语
        memory["terminology"]["terms"].append({
            "term_id": generate_id(),
            "term": updates["term"],
            "definition": updates["definition"],
            "defined_by": agent_name,
            "status": "active"
        })

    elif updates["type"] == "broadcast":
        # 广播消息
        memory["communication"]["broadcast"].append({
            "message_id": generate_id(),
            "sender": agent_name,
            "timestamp": now(),
            "type": updates["msg_type"],
            "content": updates["content"]
        })

    elif updates["type"] == "send_message":
        # 定向消息
        memory["communication"]["directed"].append({
            "message_id": generate_id(),
            "sender": agent_name,
            "recipients": updates["recipients"],
            "timestamp": now(),
            "type": updates["msg_type"],
            "content": updates["content"],
            "status": "pending"
        })

    save_json("shared_memory.json", memory)
```

---

## Memory Optimization

为了保持 context 在合理范围内：

1. **章节内容不存储在共享内存中** - 每个 agent 直接从原始论文文件读取
2. **广播消息只保留最近 50 条**
3. **已解决的定向消息归档**
4. **外部资源只存储元信息，不存储完整内容**
