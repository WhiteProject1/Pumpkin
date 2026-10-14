use std::sync::Arc;
use std::time::Duration;

use pumpkin_data::data_component_impl::EquipmentSlot;
use pumpkin_data::item::Item;
use pumpkin_inventory::build_equipment_slots;
use pumpkin_inventory::entity_equipment::EntityEquipment;
use pumpkin_inventory::player::player_inventory::PlayerInventory;
use pumpkin_inventory::player::player_screen_handler::PlayerScreenHandler;
use pumpkin_inventory::screen_handler::{InventoryPlayer, PlayerFuture, ScreenHandler};
use pumpkin_protocol::java::client::play::{
    CSetContainerContent, CSetContainerProperty, CSetContainerSlot, CSetCursorItem,
    CSetPlayerInventory, CSetSelectedSlot,
};
use pumpkin_protocol::java::server::play::SlotActionType;
use pumpkin_world::inventory::Inventory;
use pumpkin_world::item::ItemStack;
use tokio::sync::Mutex;

/// Survival player without a connection; everything it drops is collected.
struct TestPlayer {
    inventory: Arc<PlayerInventory>,
    dropped: Mutex<Vec<ItemStack>>,
}

impl InventoryPlayer for TestPlayer {
    fn drop_item(&self, item: ItemStack, _retain_ownership: bool) -> PlayerFuture<'_, ()> {
        Box::pin(async move { self.dropped.lock().await.push(item) })
    }

    fn get_inventory(&self) -> Arc<PlayerInventory> {
        self.inventory.clone()
    }

    fn has_infinite_materials(&self) -> bool {
        false
    }

    fn enqueue_inventory_packet<'a>(
        &'a self,
        _packet: &'a CSetContainerContent,
    ) -> PlayerFuture<'a, ()> {
        Box::pin(async {})
    }

    fn enqueue_slot_packet<'a>(&'a self, _packet: &'a CSetContainerSlot) -> PlayerFuture<'a, ()> {
        Box::pin(async {})
    }

    fn enqueue_cursor_packet<'a>(&'a self, _packet: &'a CSetCursorItem) -> PlayerFuture<'a, ()> {
        Box::pin(async {})
    }

    fn enqueue_property_packet<'a>(
        &'a self,
        _packet: &'a CSetContainerProperty,
    ) -> PlayerFuture<'a, ()> {
        Box::pin(async {})
    }

    fn enqueue_slot_set_packet<'a>(
        &'a self,
        _packet: &'a CSetPlayerInventory,
    ) -> PlayerFuture<'a, ()> {
        Box::pin(async {})
    }

    fn enqueue_set_held_item_packet<'a>(
        &'a self,
        _packet: &'a CSetSelectedSlot,
    ) -> PlayerFuture<'a, ()> {
        Box::pin(async {})
    }

    fn enqueue_equipment_change<'a>(
        &'a self,
        _slot: &'a EquipmentSlot,
        _stack: &'a ItemStack,
    ) -> PlayerFuture<'a, ()> {
        Box::pin(async {})
    }

    fn award_experience(&self, _amount: i32) -> PlayerFuture<'_, ()> {
        Box::pin(async {})
    }
}

async fn setup() -> (TestPlayer, PlayerScreenHandler) {
    let inventory = Arc::new(PlayerInventory::new(
        Arc::new(Mutex::new(EntityEquipment::new())),
        Arc::new(build_equipment_slots()),
    ));
    let handler = PlayerScreenHandler::new(&inventory, None, 0).await;
    let player = TestPlayer {
        inventory,
        dropped: Mutex::new(Vec::new()),
    };
    (player, handler)
}

async fn count(inventory: &PlayerInventory, slot: usize) -> u8 {
    inventory.get_stack(slot).await.lock().await.item_count
}

async fn cursor_count(handler: &PlayerScreenHandler) -> u8 {
    handler.get_behaviour().cursor_stack.lock().await.item_count
}

#[tokio::test]
async fn slot_validation_rejects_out_of_range_indices() {
    let (_, handler) = setup().await;
    let slots = handler.get_behaviour().slots.len() as i32;

    for slot in [-999, -1, 0, slots - 1] {
        assert!(handler.is_slot_valid(slot).await, "slot {slot}");
    }
    for slot in [i32::MIN, -1000, -2, slots, i32::MAX] {
        assert!(!handler.is_slot_valid(slot).await, "slot {slot}");
    }
}

#[tokio::test]
async fn swap_into_single_item_slot_does_not_duplicate() {
    let (player, mut handler) = setup().await;
    player
        .inventory
        .set_stack(0, ItemStack::new(64, &Item::CARVED_PUMPKIN))
        .await;

    // Hotbar key 1 while hovering the helmet slot (screen slot 5 -> inventory slot 39)
    handler
        .on_slot_click(5, 0, SlotActionType::Swap, &player)
        .await;

    assert_eq!(count(&player.inventory, 39).await, 1);
    assert_eq!(count(&player.inventory, 0).await, 63);
}

#[tokio::test]
async fn quick_craft_validates_drag_button_and_deduplicates_slots() {
    let (player, mut handler) = setup().await;
    *handler.get_behaviour().cursor_stack.lock().await = ItemStack::new(8, &Item::STICK);

    // Drag start, then the same slot over and over: it must only be recorded once.
    handler
        .on_slot_click(-999, 0, SlotActionType::QuickCraft, &player)
        .await;
    for _ in 0..300 {
        handler
            .on_slot_click(9, 1, SlotActionType::QuickCraft, &player)
            .await;
    }
    handler
        .on_slot_click(10, 1, SlotActionType::QuickCraft, &player)
        .await;
    assert_eq!(handler.get_behaviour().drag_slots, vec![9, 10]);

    // Drag end with drag button 3 is invalid: nothing moves and the drag is reset.
    handler
        .on_slot_click(-999, (3 << 2) | 2, SlotActionType::QuickCraft, &player)
        .await;
    assert_eq!(handler.get_behaviour().drag_slots, Vec::<u32>::new());
    assert_eq!(cursor_count(&handler).await, 8);
    assert_eq!(count(&player.inventory, 9).await, 0);

    // Drag button 2 (clone) is creative only.
    handler
        .on_slot_click(-999, 2 << 2, SlotActionType::QuickCraft, &player)
        .await;
    handler
        .on_slot_click(9, (2 << 2) | 1, SlotActionType::QuickCraft, &player)
        .await;
    handler
        .on_slot_click(10, (2 << 2) | 1, SlotActionType::QuickCraft, &player)
        .await;
    handler
        .on_slot_click(-999, (2 << 2) | 2, SlotActionType::QuickCraft, &player)
        .await;
    assert_eq!(handler.get_behaviour().drag_slots, Vec::<u32>::new());
    assert_eq!(cursor_count(&handler).await, 8);
    assert_eq!(count(&player.inventory, 9).await, 0);
    assert_eq!(count(&player.inventory, 10).await, 0);

    // A valid left drag splits the cursor evenly.
    handler
        .on_slot_click(-999, 0, SlotActionType::QuickCraft, &player)
        .await;
    handler
        .on_slot_click(9, 1, SlotActionType::QuickCraft, &player)
        .await;
    handler
        .on_slot_click(10, 1, SlotActionType::QuickCraft, &player)
        .await;
    handler
        .on_slot_click(-999, 2, SlotActionType::QuickCraft, &player)
        .await;
    assert_eq!(handler.get_behaviour().drag_slots, Vec::<u32>::new());
    assert_eq!(cursor_count(&handler).await, 0);
    assert_eq!(count(&player.inventory, 9).await, 4);
    assert_eq!(count(&player.inventory, 10).await, 4);
}

#[tokio::test]
async fn throw_all_from_crafting_result_terminates() {
    let (player, mut handler) = setup().await;
    // Two planks on top of each other in the 2x2 grid (screen slots 1 and 3) craft sticks.
    let slots = handler.get_behaviour().slots.clone();
    slots[1]
        .set_stack(ItemStack::new(64, &Item::OAK_PLANKS))
        .await;
    slots[3]
        .set_stack(ItemStack::new(64, &Item::OAK_PLANKS))
        .await;
    // Lets the result slot listener pick up the recipe.
    handler.send_content_updates().await;
    let result = slots[0].get_cloned_stack().await;
    assert!(!result.is_empty(), "the crafting grid should have a result");

    tokio::time::timeout(
        Duration::from_secs(30),
        handler.on_slot_click(0, 1, SlotActionType::Throw, &player),
    )
    .await
    .expect("throwing the whole crafting result must terminate");

    assert!(slots[0].get_cloned_stack().await.is_empty());
    assert!(slots[1].get_cloned_stack().await.is_empty());
    assert!(slots[3].get_cloned_stack().await.is_empty());
    let dropped: u32 = player
        .dropped
        .lock()
        .await
        .iter()
        .map(|stack| u32::from(stack.item_count))
        .sum();
    assert_eq!(dropped, 64 * u32::from(result.item_count));
}
