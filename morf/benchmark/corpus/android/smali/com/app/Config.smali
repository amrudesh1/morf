.class public Lcom/app/Config;
.super Ljava/lang/Object;

# TRUE POSITIVE: AWS access key id in a decompiled smali const-string.
.method public awsKey()Ljava/lang/String;
    const-string v0, "__MORF_BENCH_AWS_SMALI__"
    return-object v0
.end method

# TRUE POSITIVE: Stripe live secret key.
.method public stripe()Ljava/lang/String;
    const-string v1, "__MORF_BENCH_STRIPE__"
    return-object v1
.end method

# TRUE POSITIVE: GitHub personal access token (classic ghp_).
.method public gh()Ljava/lang/String;
    const-string v2, "__MORF_BENCH_GHP__"
    return-object v2
.end method

# DECOY: a 40-char git commit SHA quoted like a token. High-entropy but not a
# secret; no rule should attribute it (it matches no fixed-prefix pattern).
.method public gitSha()Ljava/lang/String;
    const-string v3, "9f2c1ab7d34e5f6a8b0c1d2e3f405162738495a6"
    return-object v3
.end method

# DECOY: a random UUID resource id, pure noise.
.method public uuid()Ljava/lang/String;
    const-string v4, "550e8400-e29b-41d4-a716-446655440000"
    return-object v4
.end method
