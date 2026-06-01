use std::fs::{create_dir, remove_dir_all};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{ensure, Result};
use filecoin_hashers::Hasher;
use filecoin_proofs::with_shape;
use log::{debug, info};
use rand::{thread_rng, Rng};
use storage_proofs_core::merkle::{
    generate_tree, get_base_tree_count, MerkleProofTrait, MerkleTreeTrait, MerkleTreeWrapper,
};
use storage_proofs_core::util::default_rows_to_discard;
use typenum::Unsigned;

type BenchTree<Tree> = MerkleTreeWrapper<
    <Tree as MerkleTreeTrait>::Hasher,
    <Tree as MerkleTreeTrait>::Store,
    <Tree as MerkleTreeTrait>::Arity,
    <Tree as MerkleTreeTrait>::SubTreeArity,
    <Tree as MerkleTreeTrait>::TopTreeArity,
>;

struct SectorLayout {
    base_tree_leaves: usize,
    tree_count: usize,
    nodes: usize,
}

fn sector_layout<Tree: MerkleTreeTrait>(size: usize) -> SectorLayout {
    let tree_count = get_base_tree_count::<Tree>();
    let base_tree_leaves =
        size / std::mem::size_of::<<Tree::Hasher as Hasher>::Domain>() / tree_count;
    SectorLayout {
        base_tree_leaves,
        tree_count,
        nodes: base_tree_leaves * tree_count,
    }
}

fn generate_proofs<R: Rng, Tree: MerkleTreeTrait>(
    rng: &mut R,
    tree: &BenchTree<Tree>,
    layout: &SectorLayout,
    proofs_count: usize,
    validate: bool,
) -> Result<()> {
    let proofs_count = if proofs_count >= layout.nodes {
        info!(
            "requested {} proofs, but instead challenging all {} nodes sequentially",
            proofs_count, layout.nodes
        );

        layout.nodes
    } else {
        proofs_count
    };

    info!(
        "creating {} inclusion proofs over {} nodes (validate enabled? {})",
        proofs_count, layout.nodes, validate
    );

    let rows_to_discard =
        default_rows_to_discard(layout.base_tree_leaves, Tree::Arity::to_usize());
    for i in 0..proofs_count {
        let challenge = if proofs_count == layout.nodes {
            i
        } else {
            rng.gen_range(0..layout.nodes)
        };
        debug!("challenge[{}] = {}", i, challenge);
        let proof = tree
            .gen_cached_proof(challenge, Some(rows_to_discard))
            .expect("failed to generate proof");
        if validate {
            ensure!(proof.validate(challenge), "failed to validate proof");
        }
    }

    Ok(())
}

fn build_tree_for_sector<R: Rng, Tree: 'static + MerkleTreeTrait>(
    rng: &mut R,
    size: usize,
    layout: &SectorLayout,
) -> Result<(PathBuf, BenchTree<Tree>)> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let temp_path = std::env::temp_dir().join(format!("merkle-proof-bench-{}", timestamp));
    create_dir(&temp_path)?;

    info!(
        "generating merkle tree for sector size {} [base_tree_leaves {}, tree_count {}]",
        size, layout.base_tree_leaves, layout.tree_count
    );
    let (_data, tree) = generate_tree::<Tree, _>(rng, layout.nodes, Some(temp_path.clone()));

    Ok((temp_path, tree))
}

fn run_on_shared_tree<Tree: 'static + MerkleTreeTrait>(
    size: usize,
    proofs_count: usize,
    validate: bool,
) -> Result<()> {
    let layout = sector_layout::<Tree>(size);
    let mut rng = thread_rng();
    let (temp_path, tree) = build_tree_for_sector::<_, Tree>(&mut rng, size, &layout)?;
    generate_proofs::<_, Tree>(
        &mut rng,
        &tree,
        &layout,
        proofs_count,
        validate,
    )?;
    remove_dir_all(&temp_path)?;
    Ok(())
}

fn run_fresh_tree_per_proof<Tree: 'static + MerkleTreeTrait>(
    size: usize,
    proofs_count: usize,
    validate: bool,
) -> Result<()> {
    let layout = sector_layout::<Tree>(size);
    let mut rng = thread_rng();

    info!(
        "fresh tree per proof: {} independent sectors of size {}",
        proofs_count, size
    );

    for i in 0..proofs_count {
        info!("sector {}/{}", i + 1, proofs_count);
        let (temp_path, tree) = build_tree_for_sector::<_, Tree>(&mut rng, size, &layout)?;
        generate_proofs::<_, Tree>(&mut rng, &tree, &layout, 1, validate)?;
        remove_dir_all(&temp_path)?;
    }

    Ok(())
}

pub fn run_merkleproofs_bench<Tree: 'static + MerkleTreeTrait>(
    size: usize,
    proofs_count: usize,
    validate: bool,
    fresh_tree_per_proof: bool,
) -> Result<()> {
    if fresh_tree_per_proof {
        run_fresh_tree_per_proof::<Tree>(size, proofs_count, validate)
    } else {
        run_on_shared_tree::<Tree>(size, proofs_count, validate)
    }
}

pub fn run(
    size: usize,
    proofs_count: usize,
    validate: bool,
    fresh_tree_per_proof: bool,
) -> Result<()> {
    with_shape!(
        size as u64,
        run_merkleproofs_bench,
        size,
        proofs_count,
        validate,
        fresh_tree_per_proof
    )
}
