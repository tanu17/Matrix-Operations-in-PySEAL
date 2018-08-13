# Simulate data
set.seed(2012)
n = 10000 # number of individuals
m = 1000  # number of SNPs
k = 15    # Number of covariates

# S is matrix with output as number between 0-2
S = matrix(2*runif(n*m), n, m)

y = rnorm(n)

X0 = matrix(rnorm(n*k), n, k)

#adding columns of 1 to matrix X
X = cbind(1, X0)

# Do the computations
t0 = proc.time()[1]

U1 = crossprod(X, y)
# transposeX * y

U2 = solve(crossprod(X), U1)
ytr = y - X %*% U2
U3 = crossprod(X, S)
U4 = solve(crossprod(X), U3)

Str = S - X %*% U4
Str2 = colSums(Str ^ 2)
b = as.vector(crossprod(ytr, Str) / Str2)
## calculate residual error
sig = (sum(ytr ^ 2) - (b ^ 2) * Str2) / (n - k - 2)
## calculate standard error for beta
err = sqrt(sig * (1 / Str2))
p = 2 * pnorm(-abs(b / err))
logp = -log10(p)

# Report time
t1 = proc.time()[1] - t0
msip = 1e-06 * n * m / t1
cat(sprintf("Speed: %2.1f Msips\n", msip))
