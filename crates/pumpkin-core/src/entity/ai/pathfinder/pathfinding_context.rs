use pumpkin_data::{
    Block, BlockState, BlockStateId,
    fluid::Fluid,
    tag::{self, Taggable},
};
use pumpkin_util::math::{
    boundingbox::BoundingBox, position::BlockPos, vector2::Vector2, vector3::Vector3,
};
use pumpkin_world::level::SyncChunk;

use crate::{
    entity::ai::pathfinder::{
        node::{Coordinate, PathComputationType, PathType},
        path_type_cache::PathTypeCache,
    },
    world::World,
};

use rustc_hash::FxHashMap;
use std::sync::Arc;

/// The chunks around a path search, taken once like vanilla's `PathNavigationRegion`.
struct ChunkRegion {
    min: Vector2<i32>,
    width: i32,
    depth: i32,
    chunks: Vec<Option<SyncChunk>>,
}

impl ChunkRegion {
    /// The slot for `chunk`, empty when that chunk isn't loaded; `None` outside the region.
    fn get(&self, chunk: Vector2<i32>) -> Option<&Option<SyncChunk>> {
        let x = chunk.x - self.min.x;
        let z = chunk.y - self.min.y;
        if x < 0 || z < 0 || x >= self.width || z >= self.depth {
            return None;
        }
        self.chunks.get((z * self.width + x) as usize)
    }
}

pub struct PathfindingContext {
    path_type_cache: Option<PathTypeCache>,
    mob_position: Vector3<i32>,
    world: Arc<World>,
    collision_cache: FxHashMap<[u64; 6], bool>,
    land_type_cache: FxHashMap<Vector3<i32>, PathType>,
    region: Option<ChunkRegion>,
}

impl PathfindingContext {
    #[must_use]
    pub fn new(mob_position: Vector3<i32>, world: Arc<World>) -> Self {
        Self {
            path_type_cache: Some(PathTypeCache::new()),
            mob_position,
            world,
            collision_cache: FxHashMap::default(),
            land_type_cache: FxHashMap::default(),
            region: None,
        }
    }

    #[must_use]
    pub fn with_cache(mob_position: Vector3<i32>, world: Arc<World>, cache: PathTypeCache) -> Self {
        Self {
            path_type_cache: Some(cache),
            mob_position,
            world,
            collision_cache: FxHashMap::default(),
            land_type_cache: FxHashMap::default(),
            region: None,
        }
    }

    #[must_use]
    pub const fn mob_position(&self) -> Vector3<i32> {
        self.mob_position
    }

    #[must_use]
    pub const fn world(&self) -> &Arc<World> {
        &self.world
    }

    #[must_use]
    pub const fn min_y(&self) -> i32 {
        -64
    }

    #[must_use]
    pub const fn sea_level(&self) -> i32 {
        63
    }

    pub fn get_path_type_from_state(&mut self, pos: Vector3<i32>) -> PathType {
        if let Some(ref cache) = self.path_type_cache
            && let Some(pt) = cache.get(pos)
        {
            return pt;
        }

        let pt = self.compute_path_type_from_state(pos);

        if let Some(ref mut cache) = self.path_type_cache {
            cache.insert(pos, pt);
        }

        pt
    }

    #[must_use]
    pub fn compute_path_type_from_state(&self, pos: Vector3<i32>) -> PathType {
        let block_pos = pos.as_blockpos();
        let state_id = self.block_state_id(&block_pos);
        let block = Block::from_state_id(state_id);
        let state = BlockState::from_id(state_id);

        if state.is_air() {
            return PathType::Open;
        }

        if block.has_tag(&tag::Block::MINECRAFT_TRAPDOORS)
            || block.id == Block::LILY_PAD.id
            || block.id == Block::BIG_DRIPLEAF.id
        {
            return PathType::Trapdoor;
        }

        if block.id == Block::POWDER_SNOW.id {
            return PathType::PowderSnow;
        }

        if block.id == Block::CACTUS.id || block.id == Block::SWEET_BERRY_BUSH.id {
            return PathType::DamageOther;
        }

        if block.id == Block::HONEY_BLOCK.id {
            return PathType::StickyHoney;
        }

        if block.id == Block::COCOA.id {
            return PathType::Cocoa;
        }

        if block.id == Block::WITHER_ROSE.id || block.id == Block::POINTED_DRIPSTONE.id {
            return PathType::DamageCautious;
        }

        let fluid = Fluid::from_state_id(state_id);
        if fluid.is_some_and(|f| f.has_tag(&tag::Fluid::MINECRAFT_LAVA)) {
            return PathType::Lava;
        }

        if block.id == Block::FIRE.id
            || block.id == Block::SOUL_FIRE.id
            || block.id == Block::MAGMA_BLOCK.id
            || block.id == Block::CAMPFIRE.id
            || block.id == Block::SOUL_CAMPFIRE.id
            || block.id == Block::LAVA_CAULDRON.id
        {
            return PathType::DamageFire;
        }

        if block.has_tag(&tag::Block::MINECRAFT_DOORS) {
            if state.collision_shapes.is_empty() {
                return PathType::DoorOpen;
            }

            return if block.id == Block::IRON_DOOR.id {
                PathType::DoorIronClosed
            } else {
                PathType::DoorWoodClosed
            };
        }

        if block.has_tag(&tag::Block::MINECRAFT_RAILS) {
            return PathType::Rail;
        }

        if block.has_tag(&tag::Block::MINECRAFT_LEAVES) {
            return PathType::Leaves;
        }

        if block.has_tag(&tag::Block::MINECRAFT_FENCES)
            || block.has_tag(&tag::Block::MINECRAFT_WALLS)
        {
            return PathType::Fence;
        }

        if block.has_tag(&tag::Block::MINECRAFT_FENCE_GATES) {
            return if state.collision_shapes.is_empty() {
                if fluid.is_some_and(|f| f.has_tag(&tag::Fluid::MINECRAFT_WATER)) {
                    PathType::Water
                } else {
                    PathType::Open
                }
            } else {
                PathType::Fence
            };
        }

        if !self
            .world
            .block_registry
            .is_pathfindable(block, state, PathComputationType::Land)
        {
            return PathType::Blocked;
        }

        if fluid.is_some_and(|f| f.has_tag(&tag::Fluid::MINECRAFT_WATER)) {
            return PathType::Water;
        }

        PathType::Open
    }

    /// Vanilla `WalkNodeEvaluator.getPathTypeStatic`. A search asks for the same position many
    /// times, and the answer only depends on blocks it already read, so it is kept.
    pub fn get_land_node_type(&mut self, pos: Vector3<i32>) -> PathType {
        if let Some(&cached) = self.land_type_cache.get(&pos) {
            return cached;
        }
        let land_type = self.compute_land_node_type(pos);
        self.land_type_cache.insert(pos, land_type);
        land_type
    }

    fn compute_land_node_type(&mut self, pos: Vector3<i32>) -> PathType {
        let raw_type = self.get_path_type_from_state(pos);

        if raw_type == PathType::Open && pos.y > self.min_y() {
            let below_type = self.get_path_type_from_state(Vector3::new(pos.x, pos.y - 1, pos.z));
            return match below_type {
                PathType::Open | PathType::Water | PathType::Lava | PathType::Walkable => {
                    PathType::Open
                }
                PathType::DamageFire => PathType::DamageFire,
                PathType::DamageOther => PathType::DamageOther,
                PathType::StickyHoney => PathType::StickyHoney,
                PathType::PowderSnow => PathType::DangerPowderSnow,
                PathType::DamageCautious => PathType::DamageCautious,
                PathType::Trapdoor => PathType::DangerTrapdoor,
                _ => self.get_node_type_from_neighbors(pos, PathType::Walkable),
            };
        }

        raw_type
    }

    pub fn get_node_type_from_neighbors(
        &mut self,
        pos: Vector3<i32>,
        fallback: PathType,
    ) -> PathType {
        for dy in -1..=1i32 {
            for dx in -1..=1i32 {
                for dz in -1..=1i32 {
                    if dx == 0 && dz == 0 {
                        continue;
                    }

                    let neighbor_type = self.get_path_type_from_state(Vector3::new(
                        pos.x + dx,
                        pos.y + dy,
                        pos.z + dz,
                    ));

                    if neighbor_type == PathType::DamageOther {
                        return PathType::DangerOther;
                    }
                    if neighbor_type == PathType::DamageFire || neighbor_type == PathType::Lava {
                        return PathType::DangerFire;
                    }
                    if neighbor_type == PathType::Water {
                        return PathType::WaterBorder;
                    }
                    if neighbor_type == PathType::DamageCautious {
                        return PathType::DamageCautious;
                    }
                }
            }
        }

        fallback
    }

    #[must_use]
    pub fn get_floor_level(&self, pos: &BlockPos) -> f64 {
        let target = pos.down();
        let state = BlockState::from_id(self.block_state_id(&target));
        let max_y = state
            .get_block_collision_shapes_at(&target)
            .map(|s| s.max.y)
            .fold(0.0f64, f64::max);
        f64::from(target.0.y) + max_y
    }

    pub fn has_collision(&mut self, bb: &BoundingBox) -> bool {
        let key = [
            bb.min.x.to_bits(),
            bb.min.y.to_bits(),
            bb.min.z.to_bits(),
            bb.max.x.to_bits(),
            bb.max.y.to_bits(),
            bb.max.z.to_bits(),
        ];

        if let Some(&cached) = self.collision_cache.get(&key) {
            return cached;
        }

        let min = bb.min_block_pos();
        let max = bb.max_block_pos();
        let mut collided = false;

        for pos in BlockPos::iterate(min, max) {
            let state = BlockState::from_id(self.block_state_id(&pos));
            if state.is_air() || !state.is_solid() {
                continue;
            }
            for shape in state.get_block_collision_shapes_at(&pos) {
                let world_shape = shape.at_pos(pos);
                if world_shape.intersects(bb) {
                    collided = true;
                    break;
                }
            }
            if collided {
                break;
            }
        }

        self.collision_cache.insert(key, collided);
        collided
    }

    #[must_use]
    pub fn is_water(&self, pos: &BlockPos) -> bool {
        let state_id = self.block_state_id(pos);
        let fluid = Fluid::from_state_id(state_id);
        fluid.is_some_and(|f| f.has_tag(&tag::Fluid::MINECRAFT_WATER))
    }

    #[must_use]
    pub fn is_air(&self, pos: &BlockPos) -> bool {
        BlockState::from_id(self.block_state_id(pos)).is_air()
    }

    #[must_use]
    pub fn get_block_state(&self, pos: &BlockPos) -> &'static BlockState {
        BlockState::from_id(self.block_state_id(pos))
    }

    #[must_use]
    pub fn is_pathfindable(&self, pos: &BlockPos, computation_type: PathComputationType) -> bool {
        let (block, state) = BlockState::from_id_with_block(self.block_state_id(pos));
        self.world
            .block_registry
            .is_pathfindable(block, state, computation_type)
    }

    /// Takes the chunks within `radius` blocks of the mob for the coming search, as vanilla's
    /// `PathNavigationRegion` does, so block reads there skip the world's chunk map.
    pub fn snapshot_region(&mut self, radius: i32) {
        let min = Vector2::new(
            (self.mob_position.x - radius) >> 4,
            (self.mob_position.z - radius) >> 4,
        );
        let max = Vector2::new(
            (self.mob_position.x + radius) >> 4,
            (self.mob_position.z + radius) >> 4,
        );
        let level = &self.world.level;
        let chunks = (min.y..=max.y)
            .flat_map(|z| (min.x..=max.x).map(move |x| Vector2::new(x, z)))
            .map(|chunk| level.read_chunk_sync(&chunk, Arc::clone))
            .collect();
        self.region = Some(ChunkRegion {
            min,
            width: max.x - min.x + 1,
            depth: max.y - min.y + 1,
            chunks,
        });
    }

    /// The block at `pos`. Unloaded chunks and positions outside the build limit read as air, as
    /// `World::get_block_state_id` does.
    fn block_state_id(&self, pos: &BlockPos) -> BlockStateId {
        if !self.world.is_in_build_limit(*pos) {
            return Block::AIR.default_state.id;
        }
        let (chunk_pos, relative) = pos.chunk_and_chunk_relative_position();
        let read = |chunk: &SyncChunk| {
            chunk
                .section
                .get_block_absolute_y(relative.x as usize, relative.y, relative.z as usize)
        };
        let id = self
            .region
            .as_ref()
            .and_then(|region| region.get(chunk_pos))
            .map_or_else(
                || self.world.level.read_chunk_sync(&chunk_pos, read).flatten(),
                |chunk| chunk.as_ref().and_then(read),
            );
        id.unwrap_or(Block::AIR.default_state.id)
    }

    pub fn clear_caches(&mut self) {
        if let Some(ref mut cache) = self.path_type_cache {
            cache.clear();
        }
        self.collision_cache.clear();
        self.land_type_cache.clear();
    }
}
