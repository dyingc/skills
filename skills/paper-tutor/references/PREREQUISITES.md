# Common Prerequisite Concepts

Reference guide for explaining common CS/AI concepts encountered in academic papers.

## Machine Learning Fundamentals

### Supervised Learning
Learning from labeled data to predict outputs for new inputs. Key types: classification (discrete labels) and regression (continuous values).

### Unsupervised Learning
Finding patterns in unlabeled data. Includes clustering, dimensionality reduction, and generative modeling.

### Loss Function
A measure of how wrong a model's predictions are. Training aims to minimize this function.

### Gradient Descent
Optimization algorithm that iteratively adjusts parameters to minimize loss by moving in the direction of steepest descent.

### Overfitting
When a model learns training data too well, including noise, and fails to generalize to new data. Addressed by regularization, cross-validation.

## Neural Networks

### Perceptron
Basic neural network unit: computes weighted sum of inputs + bias, applies activation function.

### Backpropagation
Algorithm to train neural networks: computes gradients of loss w.r.t. parameters using chain rule, propagating errors backward.

### Activation Functions
Introduce non-linearity: ReLU (max(0,x)), Sigmoid (1/(1+e^-x)), Tanh, Softmax (for probability distributions).

### Embedding
Low-dimensional vector representation of discrete objects (words, nodes, items) that captures semantic relationships.

## Deep Learning Architectures

### CNN (Convolutional Neural Network)
Specialized for grid-like data (images). Uses convolution layers to detect local patterns, pooling for dimensionality reduction.

### RNN (Recurrent Neural Network)
Processes sequential data by maintaining hidden state. Suffers from vanishing gradients for long sequences.

### LSTM (Long Short-Term Memory)
RNN variant with gates (input, forget, output) to control information flow, addressing vanishing gradient problem.

### Transformer
Architecture based entirely on attention mechanisms. Processes sequences in parallel using self-attention, no recurrence.

## Attention Mechanisms

### Attention
Mechanism that allows model to focus on relevant parts of input when producing output. Computes weighted sum of input representations.

### Self-Attention
Each element in sequence attends to all other elements to compute its representation. Captures dependencies regardless of distance.

### Multi-Head Attention
Runs multiple attention operations in parallel, each learning different representation subspaces.

### Key, Query, Value
Core attention components: Query (what to look for), Key (what to match against), Value (what to extract).

## Optimization

### Stochastic Gradient Descent (SGD)
Updates parameters using gradient estimate from random mini-batch of data. Faster than full-batch GD.

### Adam Optimizer
Adaptive learning rate optimizer that combines momentum and per-parameter learning rates.

### Learning Rate
Step size for parameter updates. Too large: diverge. Too small: slow convergence. Often decayed during training.

## Regularization

### Dropout
Randomly deactivate neurons during training to prevent co-adaptation and improve generalization.

### Batch Normalization
Normalizes layer inputs to reduce internal covariate shift, allowing higher learning rates.

### L1/L2 Regularization
Add penalty on parameter magnitudes to loss function. L1 encourages sparsity, L2 discourages large weights.

## Mathematics

### Gradient
Vector of partial derivatives, pointing in direction of steepest ascent. Negative gradient points toward minimum.

### Jacobian
Matrix of all first-order partial derivatives of a vector-valued function.

### Hessian
Matrix of second-order partial derivatives, used in second-order optimization methods.

### Eigenvalues/Eigenvectors
For matrix A: eigenvector v satisfies Av = λv where λ is eigenvalue. Important for PCA, stability analysis.

### Probability Distributions
- Gaussian (Normal): Bell curve, ubiquitous in nature
- Bernoulli: Binary outcomes
- Categorical: Discrete outcomes
- Uniform: All outcomes equally likely

## Information Theory

### Entropy
Measure of uncertainty in random variable. H(X) = -Σ p(x) log p(x). Higher entropy = more uncertainty.

### Cross-Entropy
Measures difference between two probability distributions. Used as loss function for classification.

### KL Divergence
Measures how one distribution differs from another. Non-symmetric measure of information loss.

## NLP Specific

### Tokenization
Splitting text into tokens (words, subwords, characters). Affects model input representation.

### Word2Vec
Learn word embeddings by predicting context words (CBOW) or target word from context (Skip-gram).

### BERT
Bidirectional encoder representations from transformers. Pre-trained on masked language modeling and next sentence prediction.

### Seq2Seq
Encoder-decoder architecture for sequence-to-sequence tasks (translation, summarization).

## Computer Vision Specific

### Convolution
Mathematical operation applying a filter/kernel to input to produce feature map.

### Pooling
Downsampling operation: max pooling (maximum value), average pooling.

### Feature Map
Output of convolution: represents detected features at spatial locations.

### Receptive Field
Region in input that influences a particular unit's activation.

## Reinforcement Learning

### Markov Decision Process (MDP)
Mathematical framework: states, actions, rewards, transition probabilities.

### Q-Learning
Learn value of taking action in state: Q(s,a). Updates using Bellman equation.

### Policy Gradient
Directly optimize policy parameters. REINFORCE is basic algorithm.

### Exploration vs Exploitation
Trade-off: try new actions (explore) vs use known good actions (exploit).

## Graph Neural Networks

### Graph Representation
Nodes (entities) and edges (relationships). Can be directed/undirected, weighted/unweighted.

### Message Passing
Nodes aggregate information from neighbors. Fundamental GNN operation.

### Graph Convolution
Aggregates neighbor features, often using adjacency matrix.

## Generative Models

### GAN (Generative Adversarial Network)
Generator creates samples, discriminator distinguishes real from fake. Adversarial training.

### VAE (Variational Autoencoder)
Encoder-decoder that learns latent representation. Probabilistic formulation with KL divergence constraint.

### Diffusion Model
Gradually add noise to data, learn to reverse process. State-of-the-art for image generation.

## Evaluation Metrics

### Precision/Recall
Precision: TP/(TP+FP) - how many selected are relevant
Recall: TP/(TP+FN) - how many relevant are selected

### F1 Score
Harmonic mean of precision and recall: 2PR/(P+R)

### BLEU (NLP)
Measures overlap of n-grams between generated and reference text.

### IoU (Computer Vision)
Intersection over Union: measures overlap between predicted and ground truth regions.

## Common Paper Sections

### Related Work
Surveys existing research, identifies gaps, positions paper's contribution.

### Ablation Study
Removing components to measure their individual contribution to performance.

### SOTA (State-of-the-Art)
Current best performance on a benchmark. Papers aim to achieve or surpass SOTA.
