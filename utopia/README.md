# Utopia Dashboard

Utopia is a Qt/QML prototype for a nocturnal potion laboratory and black-label market.

## Included

- `qml/Main.qml`: Utopia interface with Laboratory Plans and Inventory sections.
- `assets/potions/`: the five potion catalog references supplied for the shop.
- `assets/visuals/`: supplied rapper/editorial images used as atmosphere panels.
- `build/UtopiaDashboard.exe`: compiled Windows application.

## Build

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=C:\Qt\6.8.3\mingw_64
cmake --build build
```

Laboratory Plans supports six potion slots per plan with potion sprites, creating plans, assigning any of the 50 loaded accounts to different plans, an Autobuy toggle per plan that secures missing ingredients (deducting coins), and a button to open the vault chest across all accounts. Inventory shows the 50 accounts with their imaginary coin balance and a top-right button to add QW to the selected account, plus a per-account crafting record with the potions brewed in the last 7 days.
