# Figure Handling Guide

图表处理的决策树和最佳实践。

## 核心原则：图片是讲解的一部分，不是附录

**图片应该嵌入到讲解的合适位置，而不是全部放在文末。**

正确的做法：
- 在讲解概念时，选择相关的图片来增强理解
- 图片 + 文字解读 = 更好的教学效果
- 每张图片都应该有针对性的解读，帮助读者获得洞察

错误的做法：
- 把所有图片放在附录
- 只在文末列出图片链接
- 图片和讲解内容分离

---

## 图表选择流程

```
开始讲解一个概念
    │
    ▼
查看 paper_metadata.json 中的 figures 列表
    │
    ▼
是否有相关图片？
    │
    ├─ 是 ──► 读取该图片，进行 Level 2 深度分析
    │          │
    │          ▼
    │     将图片和解读嵌入到讲解中
    │
    └─ 否 ──► 继续纯文字讲解 + Mermaid 可视化
```

### 如何选择合适的图片

从 `paper_metadata.json` 的 `figures` 数组中，根据 `summary` 字段判断：

```json
{
  "figures": [
    {
      "file": "fig_3_0_abc123.png",
      "page": 3,
      "summary": "The Transformer architecture diagram showing encoder-decoder structure..."
    }
  ]
}
```

**匹配规则**：
- 讲解 "模型架构" → 选择包含 "architecture" 的图
- 讲解 "注意力机制" → 选择包含 "attention" 的图
- 讲解 "实验结果" → 选择包含 "results" 或 "table" 的图

---

## Level 2 深度分析：按需生成

当确定要使用某张图片时，**必须先读取并分析**：

### 分析 Prompt 模板

```
我正在讲解论文的「{section_title}」章节，核心概念是「{concept}」。

请分析这张图片，帮助我丰富讲解内容：

1. 这张图中有哪些视觉元素直接展示了 {concept}？
2. 有哪些细节是读者可能忽略但很重要的？
3. 图中的数据/结构揭示了什么洞察？
4. 有什么可以用来举例或类比的地方？

请提供具体的、可用于讲解的分析结果。
```

### 示例

**场景**：讲解 "Multi-Head Attention" 概念

**Level 1 Summary**: "Multi-head attention diagram showing parallel attention heads with linear projections, concatenation, and final linear layer"

**Level 2 分析结果**:
```
1. 视觉元素：
   - 8 个并行的注意力头（h=8）
   - 每个头有独立的 W^Q, W^K, W^V 投影
   - 所有头的输出拼接后通过 W^O

2. 关键细节：
   - 每个头的维度是 d_k = d_model/h = 64（不是 512）
   - 这解释了为什么计算量没有显著增加

3. 洞察：
   - 多头让模型同时关注不同类型的依赖关系
   - 类比：8 个"眼睛"同时看不同的东西

4. 可用于讲解的例子：
   - Head 1 可能关注句法（主谓关系）
   - Head 2 可能关注语义（指代消解）
```

---

## 图表类型决策

```
收到一张图表
    │
    ▼
是什么类型？
    │
    ├─ 流程图/算法 ──────────► Mermaid flowchart
    ├─ 系统架构 ──────────────► Mermaid graph
    ├─ 时序交互 ──────────────► Mermaid sequence
    ├─ 实体关系 ──────────────► Mermaid erDiagram
    ├─ 状态转换 ──────────────► Mermaid stateDiagram
    │
    ├─ 实验结果曲线 ──────────► 描述 + 原图引用
    ├─ 数据表格 ───────────────► Markdown table
    ├─ 照片/真实图像 ──────────► 描述 + 原图引用
    │
    └─ 复杂科研图 ─────────────► 尝试 Mermaid，如果太复杂则引用原图
```

---

## Mermaid 可重现的图表类型

### 1. 流程图 (flowchart)

```mermaid
graph TD
    A[开始] --> B{判断}
    B -->|是| C[动作1]
    B -->|否| D[动作2]
    C --> E[结束]
    D --> E
```

**适用于**：算法流程、处理步骤

**何时使用**：
- 原图是流程图
- 需要简化复杂流程
- 需要添加解释性标注

### 2. 架构图 (graph)

```mermaid
graph LR
    A[客户端] --> B[API网关]
    B --> C[服务1]
    B --> D[服务2]
    C --> E[数据库]
    D --> E
```

**适用于**：系统架构、模块关系

### 3. 时序图 (sequence)

```mermaid
sequenceDiagram
    用户->>系统: 请求
    系统->>数据库: 查询
    数据库-->>系统: 返回
    系统-->>用户: 响应
```

**适用于**：交互流程、API调用

### 4. 状态图 (stateDiagram)

```mermaid
stateDiagram-v2
    [*] --> 待处理
    待处理 --> 处理中
    处理中 --> 完成
    处理中 --> 失败
    完成 --> [*]
    失败 --> 待处理
```

**适用于**：状态机、生命周期

---

## 不可重现的图表类型

### 实验结果曲线

**处理方式**：描述 + 原图引用

```markdown
#### 图5：训练收敛曲线

**原图**：
![训练曲线](figures/fig_005_convergence.png)

**这张图展示了**：模型训练过程中 Loss 的变化

**如何阅读**：
1. X轴：训练步数（0 - 100k）
2. Y轴：Cross-Entropy Loss
3. 蓝线：Transformer
4. 橙线：LSTM baseline

**关键观察**：
- Transformer 收敛更快（约 20k 步）
- Transformer 最终 Loss 更低
- 两条曲线都在 50k 步后趋于稳定

**为什么重要**：
- 证明了 Transformer 的训练效率
- 暗示了模型容量优势
```

### 复杂数据图

**处理方式**：提取关键数据

```markdown
#### 表1：模型参数对比

| 参数 | Transformer | LSTM | GRU |
|------|-------------|------|-----|
| d_model | 512 | - | - |
| Layers | 6 | 2 | 2 |
| Heads | 8 | - | - |

**关键发现**：
- Transformer 使用多头注意力
- 深度网络（6层）vs 浅层网络（2层）
```

---

## 图表讲解模板

### 模板：可重现的图

```markdown
#### 图X：[标题]

**原图引用**：
![原图](figures/fig_xxx.png)

**这个图展示了**：[核心内容]

**简化流程图**：
```mermaid
[Mermaid 代码]
```

**关键组件**：
- 组件A：[作用]
- 组件B：[作用]

**数据流动**：
1. [步骤1]
2. [步骤2]
3. [步骤3]

**与其他章节的关联**：
- 依赖章节X的概念Y
- 被章节Z引用
```

### 模板：不可重现的图

```markdown
#### 图X：[标题]

**原图引用**：
![原图](figures/fig_xxx.png)

**图意**：这张图想要表达的是...

**如何阅读**：
1. 首先看X轴代表...
2. Y轴表示...
3. 不同颜色/形状的线/柱表示...

**关键发现**：
- 发现1：[描述]
- 发现2：[描述]
- 发现3：[描述]

**深入理解**：
这个图的关键洞察是...

**与其他章节的关联**：
- 验证了章节X的结论
- 与章节Y的图Z对比...
```

---

## 查找和引用图表

### 在共享内存中查找

```python
# 按页查找
figures = find_figures(page=5, chapter="ch3")

# 按编号查找
figures = find_figures(figure_number="Figure 1")

# 获取图片并确保有理解
fig = get_figure_with_understanding("fig_001")
```

### 在 Markdown 中引用

```markdown
# 方式1：相对路径
![Transformer架构](figures/fig_001_transformer_architecture.png)

# 方式2：使用共享内存中的路径
![Transformer架构](@figures/fig_001_transformer_architecture.png)

# 方式3：带链接
[点击查看大图](figures/fig_001_transformer_architecture.png)
```
