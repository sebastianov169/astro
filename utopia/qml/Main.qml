import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window

ApplicationWindow {
    id: root
    width: 1440
    height: 900
    minimumWidth: 1120
    minimumHeight: 720
    visible: true
    title: "Utopia"
    color: colors.canvas

    QtObject {
        id: colors
        readonly property color canvas: "#040810"
        readonly property color surface: "#08131f"
        readonly property color surface2: "#0d1d2b"
        readonly property color surface3: "#142c40"
        readonly property color border: "#20506a"
        readonly property color borderSoft: "#17384e"
        readonly property color text: "#f0fbff"
        readonly property color muted: "#8baebb"
        readonly property color faint: "#52788a"
        readonly property color teal: "#48f1da"
        readonly property color purple: "#aa8cff"
        readonly property color gold: "#f3c85b"
        readonly property color danger: "#dd526c"
        readonly property color wine: "#6e213b"
    }

    property int section: 0
    property int coins: 12450
    property int activePlan: 0
    property var accountPlans: []
    property var planSlots: [
        ["Superior Blink", "Mythical Speed Potion", "Speed Anticellular Shield", "Powerful Portal Glue", "Super Glue Potion", "Legendary Speed Potion"],
        ["Legendary Blink", "Speed & Gravity Potion", "Legendary Gravity Potion", "Powerful Portal Glue", "Anticellular Armor", "Superior Blink"],
        ["Speed Shot", "Legendary Speed Potion", "Portal Shield Armor", "Superior Portal Gun", "Bubble Gun", "Superior Gravity Blink"]
    ]
    property var ingredientPool: ["Violet residue", "Cold glass", "Unstable core", "Moon salt", "Night pollen", "Sulfuric dew", "Crystal shard", "Ash dust"]
    property var potionIngredients: {}
    property var ingredientStock: {}
    property var planAutobuy: []
property var planLoop: []
property var loopPrevSlots: {}
property var loopDoneKeys: {}
property int lastLoopScanTick: 0
    property bool showToast: false
    property string toastText: ""
    property int selectedCraftAccount: 0
    property int selectedAccount: 0
    property int planRenameIndex: -1
property var liveLabs: []
property int labTickCount: 0
property var buySelection: []
property var planActionQueue: []
property var planActionNames: []
property bool planActionIsAutobuy: false
property int buyPacks: 1
property int buyPacksItemId: 0
property string buyPacksItemName: ""
property int buyPacksItemPack: 1
    property var shopItems: [
        {name: "Tournament Ticket", id: 510, price: 200, img: "tournament-ticket.png", pack: 1},
        {name: "Double Gem XP", id: 8590, price: 1200, img: "double-gem-xp.png", pack: 1},
        {name: "Self Destroying Device", id: 2147, price: 600, img: "self-destroying-device.png", pack: 20},
        {name: "Triple Coins", id: 2017, price: 600, img: "triple-coins.png", pack: 20},
        {name: "Double XP", id: 2016, price: 600, img: "double-xp.png", pack: 20},
        {name: "Virus Replication Vial", id: 2015, price: 600, img: "virus-replication-vial.png", pack: 20},
        {name: "Improved Mass Gainer", id: 2014, price: 600, img: "improved-mass-gainer.png", pack: 20},
        {name: "Adrenaline Shot", id: 2013, price: 600, img: "adrenaline-shot.png", pack: 20},
        {name: "Close Split Capsule", id: 2012, price: 600, img: "close-split-capsule.png", pack: 20},
        {name: "Nutrient Radar", id: 2011, price: 600, img: "nutrient-radar.png", pack: 20},
        {name: "Improved Mitosis", id: 2010, price: 600, img: "improved-mitosis.png", pack: 20},
        {name: "Ghostly Spyglass", id: 2009, price: 600, img: "ghostly-spyglass.png", pack: 20},
        {name: "Treasure Map", id: 2008, price: 600, img: "treasure-map.png", pack: 20},
        {name: "Powerful Portal Glue", id: 1654, price: 1000, img: "powerful-portal-glue.png", pack: 3},
        {name: "Extreme Rejoin Speed", id: 1646, price: 600, img: "extreme-rejoin-speed.png", pack: 3},
        {name: "Superior Rejoin Speed", id: 1645, price: 400, img: "superior-rejoin-speed.png", pack: 3},
        {name: "Greater Rejoin Speed", id: 1644, price: 300, img: "greater-rejoin-speed.png", pack: 3},
        {name: "Bubble Gun", id: 1494, price: 600, img: "bubble-gun.png", pack: 20},
        {name: "Anti Resilience Potion", id: 1150, price: 400, img: "anti-resilience-potion.png", pack: 4},
        {name: "Anabolic Feed Potion", id: 684, price: 300, img: "anabolic-feed-potion.png", pack: 10},
        {name: "Squeeze-o-mator", id: 668, price: 250, img: "squeeze-o-mator.png", pack: 3},
        {name: "Red Virus Seed", id: 460, price: 600, img: "red-virus-seed.png", pack: 3},
        {name: "Powerful Glue Launcher", id: 457, price: 400, img: "powerful-glue-launcher.png", pack: 5},
        {name: "Mega Split", id: 331, price: 300, img: "mega-split.png", pack: 3},
        {name: "Extreme Power Split", id: 329, price: 300, img: "extreme-power-split.png", pack: 3},
        {name: "Superior Power Split", id: 328, price: 200, img: "superior-power-split.png", pack: 3},
        {name: "Greater Power Split", id: 327, price: 150, img: "greater-power-split.png", pack: 3},
        {name: "Rudimental Chainsaw", id: 322, price: 200, img: "rudimental-chainsaw.png", pack: 5},
        {name: "Steady Chainsaw", id: 321, price: 250, img: "steady-chainsaw.png", pack: 5},
        {name: "Powerful Chainsaw", id: 320, price: 500, img: "powerful-chainsaw.png", pack: 5},
        {name: "Perfect Timewarp Machine", id: 277, price: 500, img: "perfect-timewarp-machine.png", pack: 1},
        {name: "Precise Timewarp Machine", id: 276, price: 350, img: "precise-timewarp-machine.png", pack: 1},
        {name: "Rough Timewarp Machine", id: 275, price: 250, img: "rough-timewarp-machine.png", pack: 1},
        {name: "Superior Portal Gun", id: 274, price: 600, img: "superior-portal-gun.png", pack: 5},
        {name: "Portal Gun", id: 272, price: 400, img: "portal-gun.png", pack: 4},
        {name: "Minor Portal Gun", id: 271, price: 300, img: "minor-portal-gun.png", pack: 3},
        {name: "Thor's Golden Hammer", id: 213, price: 500, img: "thors-golden-hammer.png", pack: 5},
        {name: "Insane Dwarf Beer", id: 210, price: 500, img: "insane-dwarf-beer.png", pack: 5},
        {name: "Powerful Nets Launcher", id: 158, price: 300, img: "powerful-nets-launcher.png", pack: 5},
        {name: "Superior Petrifying Shoot", id: 156, price: 600, img: "superior-petrifying-shoot.png", pack: 3},
        {name: "Superior Anticellular Shield", id: 148, price: 400, img: "superior-anticellular-shield.png", pack: 5},
        {name: "Anticellular Shield", id: 147, price: 200, img: "anticellular-shield.png", pack: 4},
        {name: "Superior Antiviral Shield", id: 145, price: 300, img: "superior-antiviral-shield.png", pack: 5},
        {name: "Antiviral Shield", id: 144, price: 200, img: "antiviral-shield.png", pack: 4},
        {name: "Mega Punch Device", id: 108, price: 450, img: "mega-punch-device.png", pack: 4},
        {name: "Punch Device", id: 107, price: 200, img: "punch-device.png", pack: 4},
        {name: "Superior Blink", id: 104, price: 600, img: "superior-blink.png", pack: 5},
        {name: "Blink", id: 103, price: 300, img: "blink.png", pack: 4},
        {name: "Superior Gravity Potion", id: 101, price: 200, img: "superior-gravity-potion.png", pack: 5},
        {name: "Gravity Potion", id: 100, price: 120, img: "gravity-potion.png", pack: 5},
        {name: "Super Glue Potion", id: 98, price: 360, img: "super-glue-potion.png", pack: 3},
        {name: "Mythical Speed Potion", id: 97, price: 300, img: "mythical-speed-potion.png", pack: 3},
        {name: "Major Speed Potion", id: 96, price: 150, img: "major-speed-potion.png", pack: 3},
        {name: "Light Speed Potion", id: 95, price: 100, img: "light-speed-potion.png", pack: 3}
    ]

    ListModel {
        id: shopModel
        ListElement { name: "Superior Blink"; type: "MOBILITY"; price: 600; catalog: "catalog-05.png"; clipX: 285; clipY: 392; clipW: 140; clipH: 78 }
        ListElement { name: "Blink"; type: "MOBILITY"; price: 300; catalog: "catalog-05.png"; clipX: 510; clipY: 392; clipW: 140; clipH: 78 }
        ListElement { name: "Mythical Speed Potion"; type: "SPEED"; price: 300; catalog: "catalog-05.png"; clipX: 280; clipY: 710; clipW: 160; clipH: 78 }
        ListElement { name: "Superior Gravity Potion"; type: "CONTROL"; price: 200; catalog: "catalog-05.png"; clipX: 740; clipY: 392; clipW: 150; clipH: 78 }
        ListElement { name: "Anti Resilience Potion"; type: "DEFENSE"; price: 400; catalog: "catalog-02.png"; clipX: 505; clipY: 392; clipW: 160; clipH: 78 }
        ListElement { name: "Anabolic Feed Potion"; type: "BOOST"; price: 300; catalog: "catalog-02.png"; clipX: 740; clipY: 392; clipW: 160; clipH: 78 }
        ListElement { name: "Powerful Portal Glue"; type: "UTILITY"; price: 1000; catalog: "catalog-02.png"; clipX: 505; clipY: 72; clipW: 160; clipH: 78 }
        ListElement { name: "Superior Portal Gun"; type: "PORTAL"; price: 600; catalog: "catalog-04.png"; clipX: 685; clipY: 78; clipW: 150; clipH: 60 }
        ListElement { name: "Powerful Chainsaw"; type: "WEAPON"; price: 500; catalog: "catalog-03.png"; clipX: 935; clipY: 382; clipW: 160; clipH: 78 }
        ListElement { name: "Superior Anticellular Shield"; type: "SHIELD"; price: 400; catalog: "catalog-05.png"; clipX: 45; clipY: 62; clipW: 150; clipH: 78 }
        ListElement { name: "Super Glue Potion"; type: "UTILITY"; price: 360; catalog: "catalog-05.png"; clipX: 45; clipY: 710; clipW: 150; clipH: 78 }
        ListElement { name: "Light Speed Potion"; type: "SPEED"; price: 100; catalog: "catalog-05.png"; clipX: 745; clipY: 710; clipW: 150; clipH: 78 }
    }

// Catalogo del LABORATORIO: las 18 recetas que el lab puede craftear
ListModel {
    id: labModel
    ListElement { name: "Mythical Speed Potion"; type: "SPEED"; price: 300; img: "mythical-speed-potion.png" }
    ListElement { name: "Powerful Portal Glue"; type: "UTILITY"; price: 1000; img: "powerful-portal-glue.png" }
    ListElement { name: "Speed Shot"; type: "SPEED"; price: 150; img: "speed-shot.png" }
    ListElement { name: "Speed Anticellular Shield"; type: "SHIELD"; price: 400; img: "speed-anticellular-shield.png" }
    ListElement { name: "Speed & Gravity Potion"; type: "CONTROL"; price: 200; img: "speed-and-gravity-potion.png" }
    ListElement { name: "Powerful Chainsaw"; type: "WEAPON"; price: 500; img: "powerful-chainsaw.png" }
    ListElement { name: "Portal Shield Armor"; type: "SHIELD"; price: 300; img: "portal-shield-armor.png" }
    ListElement { name: "Legendary Speed Potion"; type: "SPEED"; price: 600; img: "legendary-speed-potion.png" }
    ListElement { name: "Legendary Gravity Potion"; type: "CONTROL"; price: 600; img: "legendary-gravity-potion.png" }
    ListElement { name: "Legendary Blink"; type: "MOBILITY"; price: 300; img: "legendary-blink.png" }
    ListElement { name: "Super Glue Potion"; type: "UTILITY"; price: 360; img: "super-glue-potion.png" }
    ListElement { name: "Superior Portal Gun"; type: "PORTAL"; price: 600; img: "superior-portal-gun.png" }
    ListElement { name: "Anticellular Armor"; type: "SHIELD"; price: 200; img: "anticellular-armor.png" }
    ListElement { name: "Superior Blink"; type: "MOBILITY"; price: 600; img: "superior-blink.png" }
    ListElement { name: "Bubble Gun"; type: "WEAPON"; price: 600; img: "bubble-gun.png" }
    ListElement { name: "Antiviral Portal Gun"; type: "PORTAL"; price: 400; img: "antiviral-portal-gun.png" }
    ListElement { name: "Superior Immunity Shield"; type: "SHIELD"; price: 300; img: "superior-immunity-shield.png" }
    ListElement { name: "Superior Gravity Blink"; type: "CONTROL"; price: 400; img: "superior-gravity-blink.png" }
}

    ListModel {
        id: plansModel
        ListElement { name: "Night Run"; tag: "20 accounts"; planColor: "#a77bff" }
        ListElement { name: "Vault Run"; tag: "30 accounts"; planColor: "#42d8c5" }
        ListElement { name: "Clean Exit"; tag: "0 accounts"; planColor: "#e5b64e" }
    }

    property var fullCatalog: [
        {name:"Double Gem XP", type:"BOOST", price:600, catalog:"catalog-01.png", clipX:55, clipY:62, clipW:150, clipH:78},
        {name:"Self Destroying Device", type:"DEVICE", price:600, catalog:"catalog-01.png", clipX:295, clipY:62, clipW:150, clipH:78},
        {name:"Triple Coins", type:"BOOST", price:600, catalog:"catalog-01.png", clipX:535, clipY:62, clipW:150, clipH:78},
        {name:"Double XP", type:"BOOST", price:600, catalog:"catalog-01.png", clipX:775, clipY:62, clipW:150, clipH:78},
        {name:"Virus Replication Vial", type:"VIRUS", price:600, catalog:"catalog-01.png", clipX:1015, clipY:62, clipW:150, clipH:78},
        {name:"Improved Mass Gainer", type:"BOOST", price:600, catalog:"catalog-01.png", clipX:55, clipY:395, clipW:150, clipH:78},
        {name:"Adrenaline Shot", type:"SPEED", price:600, catalog:"catalog-01.png", clipX:295, clipY:395, clipW:150, clipH:78},
        {name:"Close Split Capsule", type:"UTILITY", price:600, catalog:"catalog-01.png", clipX:535, clipY:395, clipW:150, clipH:78},
        {name:"Nutrient Radar", type:"UTILITY", price:600, catalog:"catalog-01.png", clipX:775, clipY:395, clipW:150, clipH:78},
        {name:"Improved Mitosis", type:"BOOST", price:600, catalog:"catalog-01.png", clipX:1015, clipY:395, clipW:150, clipH:78},
        {name:"Ghostly Spyglass", type:"UTILITY", price:600, catalog:"catalog-02.png", clipX:45, clipY:62, clipW:150, clipH:78},
        {name:"Treasure Map", type:"UTILITY", price:600, catalog:"catalog-02.png", clipX:275, clipY:62, clipW:150, clipH:78},
        {name:"Extreme Rejoin Speed", type:"SPEED", price:600, catalog:"catalog-02.png", clipX:735, clipY:62, clipW:150, clipH:78},
        {name:"Superior Rejoin Speed", type:"SPEED", price:400, catalog:"catalog-02.png", clipX:965, clipY:62, clipW:150, clipH:78},
        {name:"Greater Rejoin Speed", type:"SPEED", price:300, catalog:"catalog-02.png", clipX:45, clipY:395, clipW:150, clipH:78},
        {name:"Bubble Gun", type:"WEAPON", price:600, catalog:"catalog-02.png", clipX:275, clipY:395, clipW:150, clipH:78},
        {name:"Squeeze-o-mator", type:"UTILITY", price:250, catalog:"catalog-02.png", clipX:965, clipY:395, clipW:150, clipH:78},
        {name:"Tournament Ticket", type:"EVENT", price:4000, catalog:"catalog-03.png", clipX:45, clipY:62, clipW:150, clipH:78},
        {name:"Red Virus Seed", type:"VIRUS", price:600, catalog:"catalog-03.png", clipX:275, clipY:62, clipW:150, clipH:78},
        {name:"Powerful Glue Launcher", type:"WEAPON", price:400, catalog:"catalog-03.png", clipX:505, clipY:62, clipW:150, clipH:78},
        {name:"Mega Split", type:"SPLIT", price:300, catalog:"catalog-03.png", clipX:735, clipY:62, clipW:150, clipH:78},
        {name:"Extreme Power Split", type:"SPLIT", price:300, catalog:"catalog-03.png", clipX:965, clipY:62, clipW:150, clipH:78},
        {name:"Superior Power Split", type:"SPLIT", price:200, catalog:"catalog-03.png", clipX:45, clipY:395, clipW:150, clipH:78},
        {name:"Greater Power Split", type:"SPLIT", price:150, catalog:"catalog-03.png", clipX:275, clipY:395, clipW:150, clipH:78},
        {name:"Rudimental Chainsaw", type:"WEAPON", price:200, catalog:"catalog-03.png", clipX:505, clipY:395, clipW:150, clipH:78},
        {name:"Steady Chainsaw", type:"WEAPON", price:250, catalog:"catalog-03.png", clipX:735, clipY:395, clipW:150, clipH:78},
        {name:"Perfect Timewarp Machine", type:"TIME", price:500, catalog:"catalog-04.png", clipX:45, clipY:62, clipW:150, clipH:78},
        {name:"Precise Timewarp Machine", type:"TIME", price:350, catalog:"catalog-04.png", clipX:275, clipY:62, clipW:150, clipH:78},
        {name:"Rough Timewarp Machine", type:"TIME", price:250, catalog:"catalog-04.png", clipX:505, clipY:62, clipW:150, clipH:78},
        {name:"Portal Gun", type:"PORTAL", price:400, catalog:"catalog-04.png", clipX:910, clipY:62, clipW:150, clipH:78},
        {name:"Minor Portal Gun", type:"PORTAL", price:300, catalog:"catalog-04.png", clipX:45, clipY:395, clipW:150, clipH:78},
        {name:"Thor's Golden Hammer", type:"WEAPON", price:500, catalog:"catalog-04.png", clipX:275, clipY:395, clipW:150, clipH:78},
        {name:"Insane Dwarf Beer", type:"BOOST", price:500, catalog:"catalog-04.png", clipX:505, clipY:395, clipW:150, clipH:78},
        {name:"Powerful Nets Launcher", type:"WEAPON", price:300, catalog:"catalog-04.png", clipX:735, clipY:395, clipW:150, clipH:78},
        {name:"Superior Petrifying Shoot", type:"CONTROL", price:600, catalog:"catalog-04.png", clipX:965, clipY:395, clipW:150, clipH:78},
        {name:"Anticellular Shield", type:"SHIELD", price:200, catalog:"catalog-05.png", clipX:275, clipY:62, clipW:150, clipH:78},
        {name:"Superior Antiviral Shield", type:"SHIELD", price:300, catalog:"catalog-05.png", clipX:505, clipY:62, clipW:150, clipH:78},
        {name:"Antiviral Shield", type:"SHIELD", price:200, catalog:"catalog-05.png", clipX:735, clipY:62, clipW:150, clipH:78},
        {name:"Mega Punch Device", type:"WEAPON", price:450, catalog:"catalog-05.png", clipX:965, clipY:62, clipW:150, clipH:78},
        {name:"Punch Device", type:"WEAPON", price:200, catalog:"catalog-05.png", clipX:45, clipY:392, clipW:150, clipH:78},
        {name:"Gravity Potion", type:"CONTROL", price:120, catalog:"catalog-05.png", clipX:965, clipY:392, clipW:150, clipH:78},
        {name:"Major Speed Potion", type:"SPEED", price:150, catalog:"catalog-05.png", clipX:505, clipY:710, clipW:150, clipH:78}
    ]

    function toast(message) {
        toastText = message
        showToast = true
        toastTimer.restart()
    }

    function activePlanName() {
        return plansModel.get(root.activePlan).name
    }

    function accountPlan(index) {
        return root.accountPlans[index] || "Unassigned"
    }

    function craftHistorySummary(history) {
        if (!history || history.length === 0)
            return "No completed crafts tracked yet"
        var summary = []
        for (var i = 0; i < history.length; ++i) {
            var entry = history[i]
            var n = String(entry.name || "").replace(/^\d+x\s*/, "").trim()
            var count = entry.count || 0
            // migracion: historiales viejos guardaban crafteos (x1), no pociones.
            // si no tienen el campo qty, multiplicar por la cantidad de la receta
            if (entry.qty === undefined) {
                var m = String(entry.name || "").match(/^(\d+)x/)
                var base = root.baseQtyFromName("3x " + n)
                if (base > 0) count = count * base
            }
            summary.push(count + "x " + n)
        }
        return summary.join("   ")
    }

    // cantidad real de pociones de una entrada del historial (migra historiales
    // viejos que guardaban crafteos x1 en vez de pociones)
    function historyCount(entry) {
        var count = entry.count || 0
        if (entry.qty === undefined) {
            var n = String(entry.name || "").replace(/^\d+x\s*/, "").trim()
            var base = root.baseQtyFromName("3x " + n)
            if (base > 0) count = count * base
        }
        return count
    }

    // total real de pociones crafteadas de una cuenta (suma con migracion)
    function totalCrafted(account) {
        var h = account.craftHistory || []
        var t = 0
        for (var i = 0; i < h.length; ++i)
            t += root.historyCount(h[i])
        return t > 0 ? t : (account.craftCount || 0)
    }

    // sprite del lab para el nombre guardado en el historial (sin prefijo "3x")
    function historyImgForName(name) {
        var n = String(name || "").replace(/^\d+x\s*/, "").trim()
        var i = potionIndexForName(n)
        return "qrc:/Utopia/assets/potions/lab_sprites/" + labModel.get(i).img
    }

function assignedToActivePlan(index) {
    return accountPlan(index) === activePlanName()
}

// qty base de la receta desde el nombre del server (ej "3x X" -> 3, "5x X" -> 5)
function baseQtyFromName(name) {
    if (!name) return 0
    var m = String(name).match(/^(\d+)x\s*/)
    return m ? parseInt(m[1]) : 0
}

// Cantidad base de cada receta del laboratorio. El endpoint a veces separa
// `name` y `qty`, por lo que no siempre llega el prefijo "3x" en el nombre.
function labRecipeBaseQty(name) {
    var clean = String(name || "").replace(/^\d+x\s*/i, "").trim()
    var quantities = {
        "Mythical Speed Potion": 3,
        "Powerful Portal Glue": 3,
        "Speed Shot": 3,
        "Speed Anticellular Shield": 3,
        "Speed & Gravity Potion": 3,
        "Powerful Chainsaw": 5,
        "Portal Shield Armor": 3,
        "Legendary Speed Potion": 2,
        "Legendary Gravity Potion": 2,
        "Legendary Blink": 2,
        "Super Glue Potion": 3,
        "Superior Portal Gun": 3,
        "Anticellular Armor": 3,
        "Superior Blink": 3,
        "Bubble Gun": 5,
        "Antiviral Portal Gun": 3,
        "Superior Immunity Shield": 3,
        "Superior Gravity Blink": 3
    }
    return quantities[clean] || 0
}

function accountLabMultiplier(accountIndex) {
    var account = loginBridge.accounts[accountIndex]
    var value = account && account.labMultiplier !== undefined ? Number(account.labMultiplier) : 1
    return value >= 3 ? 3 : (value >= 2 ? 2 : 1)
}

function liveLabForAccount(accountIndex) {
    var account = loginBridge.accounts[accountIndex]
    var deviceId = account ? String(account.deviceId || "") : ""
    if (deviceId !== "") {
        for (var i = 0; i < root.liveLabs.length; ++i) {
            if (String(root.liveLabs[i].deviceId || "") === deviceId)
                return root.liveLabs[i]
        }
    }
    return root.liveLabs[accountIndex]
}

// Combina el boost elegido en Assign accounts con el qty real que devuelve
// el servidor. El mayor valor gana, así el servidor también puede descubrir
// automáticamente una cuenta x2/x3 aunque todavía no se haya guardado localmente.
function labMultiplier(accountIndex) {
    var maxMult = root.accountLabMultiplier(accountIndex)
    var acc = root.liveLabForAccount(accountIndex)
    if (!acc || !acc.ok)
        return maxMult

    var slots = acc.slots || []
    for (var i = 0; i < slots.length; ++i) {
        var s = slots[i]
        if (s.status !== "crafting" || !s.name) continue
        var base = root.baseQtyFromName(s.name) || root.labRecipeBaseQty(s.name)
        var qty = Number(s.qty || 0)
        if (base <= 0 || qty <= 0) continue
        if (qty >= base * 3) maxMult = Math.max(maxMult, 3)
        else if (qty >= base * 2) maxMult = Math.max(maxMult, 2)
    }
    return maxMult
}

function labMultiplierLabel(accountIndex) {
    return "x" + root.labMultiplier(accountIndex) + " LAB"
}

function setAccountLabMultiplier(accountIndex, multiplier) {
    var value = Math.max(1, Math.min(3, Number(multiplier) || 1))
    loginBridge.setAccountLabMultiplier(accountIndex, value)
    toast("Account lab multiplier set to x" + value)
}

function labSlotDisplayName(slot, accountIndex) {
    if (!slot || !slot.name)
        return "READY"
    if (slot.status !== "crafting")
        return "READY"

    var raw = String(slot.name)
    var base = root.baseQtyFromName(raw) || root.labRecipeBaseQty(raw)
    var clean = raw.replace(/^\d+x\s*/, "").trim()
    if (base <= 0)
        base = 1

    // Prefer the server qty when it is higher, otherwise apply the account
    // boost so x3 turns a 3x recipe into 9x in Account Labs.
    var serverQty = Number(slot.qty || 0)
    var effectiveQty = Math.max(serverQty, base * root.labMultiplier(accountIndex))
    return effectiveQty + "x " + clean
}

// true si el plan asignado a la cuenta tiene LOOP activo
function accountLoopActive(accountIndex) {
    var planName = root.accountPlan(accountIndex)
    if (!planName || planName === "Unassigned") return false
    for (var i = 0; i < plansModel.count; ++i) {
        if (plansModel.get(i).name === planName)
            return root.planLoop[i] === true
    }
    return false
}

    function assignedCount(planName) {
        var total = 0
        for (var i = 0; i < root.accountPlans.length; ++i) {
            if (root.accountPlans[i] === planName)
                ++total
        }
        return total
    }

function togglePlanAccount(index) {
    var next = root.accountPlans.slice()
    next[index] = assignedToActivePlan(index) ? "Unassigned" : activePlanName()
    root.accountPlans = next
    // persistir la asignacion en accounts.json para que sobreviva al reinicio
    loginBridge.setAccountPlan(index, next[index])
}

    function potionIndexForName(name) {
        for (var i = 0; i < labModel.count; ++i) {
            if (labModel.get(i).name === name)
                return i
        }
        return 0
    }

function setPlanSlot(slotIndex, potionName) {
    var next = root.planSlots.map(function(slots) { return (slots || []).slice() })
    while (next.length <= root.activePlan)
        next.push([])
    while (next[root.activePlan].length <= slotIndex)
        next[root.activePlan].push("")
    next[root.activePlan][slotIndex] = potionName
    root.planSlots = next
    root.savePlansNow()
}

function slotPotionImg(slotIndex) {
    var plan = root.planSlots[root.activePlan] || []
    var name = plan[slotIndex] || "Mythical Speed Potion"
    var i = potionIndexForName(name)
    return "qrc:/Utopia/assets/potions/lab_sprites/" + labModel.get(i).img
}

// Version para binding reactivo: recibe el NOMBRE (el binding lee planSlots
// directamente, asi QML detecta el cambio y refresca el sprite)
function slotPotionImgForName(name) {
    var i = potionIndexForName(name || "Mythical Speed Potion")
    return "qrc:/Utopia/assets/potions/lab_sprites/" + labModel.get(i).img
}

// Mapea el nombre del slot del server (español, ej "3x Poción Mítica de Velocidad")
// al sprite del lab (solo sprites de la carpeta Sprites Laboratory)
function labImgForServerName(name) {
    if (!name) return ""
    var clean = String(name).replace(/^\s*\d+\s*x\s*/i, "").trim()
    var spriteMap = {
        // English names returned by the laboratory endpoint.
        "Mythical Speed Potion": "mythical-speed-potion.png",
        "Powerful Portal Glue": "powerful-portal-glue.png",
        "Speed Shot": "speed-shot.png",
        "Speed Anticellular Shield": "speed-anticellular-shield.png",
        "Speed & Gravity Potion": "speed-and-gravity-potion.png",
        "Powerful Chainsaw": "powerful-chainsaw.png",
        "Portal Shield Armor": "portal-shield-armor.png",
        "Legendary Speed Potion": "legendary-speed-potion.png",
        "Legendary Gravity Potion": "legendary-gravity-potion.png",
        "Legendary Blink": "legendary-blink.png",
        "Super Glue Potion": "super-glue-potion.png",
        "Superior Portal Gun": "superior-portal-gun.png",
        "Superior Antiviral Portal Gun": "antiviral-portal-gun.png",
        "Anticellular Armor": "anticellular-armor.png",
        "Superior Blink": "superior-blink.png",
        "Bubble Gun": "bubble-gun.png",
        "Antiviral Portal Gun": "antiviral-portal-gun.png",
        "Superior Immunity Shield": "superior-immunity-shield.png",
        "Superior Gravity Blink": "superior-gravity-blink.png",

        // Spanish names used by older laboratory responses.
        "Poción Mítica de Velocidad": "mythical-speed-potion.png",
        "Pegamento para Portal Superior": "powerful-portal-glue.png",
        "Disparo de Velocidad": "speed-shot.png",
        "Escudo Anticelular de Velocidad": "speed-anticellular-shield.png",
        "Poción de Velocidad y Gravedad": "speed-and-gravity-potion.png",
        "Martillo Motosierra de Thor": "powerful-chainsaw.png",
        "Armadura Portal de Escudo": "portal-shield-armor.png",
        "Poción Legendaria de Velocidad": "legendary-speed-potion.png",
        "Poción Legendaria de Gravedad": "legendary-gravity-potion.png",
        "Parpadeo Legendario": "legendary-blink.png",
        "Poción de Súper Pegamento": "super-glue-potion.png",
        "Pistola de Portales Superior": "superior-portal-gun.png",
        "Armadura Anticelular": "anticellular-armor.png",
        "Parpadeo Superior": "superior-blink.png",
        "Arma Burbuja": "bubble-gun.png",
        "Pistola Portal Antiviral": "antiviral-portal-gun.png",
        "Escudo Inmunis Superior": "superior-immunity-shield.png",
        "Parpadeo Gravedad Superior": "superior-gravity-blink.png",
        "Pistola de Portales Antiviral Superior": "antiviral-portal-gun.png"
    }
    if (spriteMap[clean])
        return "qrc:/Utopia/assets/potions/lab_sprites/" + spriteMap[clean]
    // Do not show an unrelated potion when the API adds a new name.
    return ""
}

    function potionIngredientsFor(name) {
        return root.potionIngredients[name] || []
    }

    function planMissingIngredients(planIndex) {
        var missing = []
        var slots = root.planSlots[planIndex] || []
        for (var s = 0; s < slots.length; ++s) {
            var ings = root.potionIngredientsFor(slots[s])
            for (var i = 0; i < ings.length; ++i) {
                if ((root.ingredientStock[ings[i]] || 0) < 1 && missing.indexOf(ings[i]) < 0)
                    missing.push(ings[i])
            }
        }
        return missing
    }

    function planMissingCount(planIndex) {
        return root.planMissingIngredients(planIndex).length
    }

function toggleAutobuy(planIndex) {
    var next = root.planAutobuy.slice()
    next[planIndex] = !next[planIndex]
    root.planAutobuy = next
    root.savePlansNow()
}

function toggleLoop(planIndex) {
    var next = root.planLoop.slice()
    next[planIndex] = !next[planIndex]
    root.planLoop = next
    root.savePlansNow()
}

    function autobuyIngredients(planIndex) {
        var missing = root.planMissingIngredients(planIndex)
        if (missing.length === 0) {
            toast("All ingredients already in stock")
            return
        }
        var cost = missing.length * 250
        if (root.coins < cost) {
            toast("Not enough coins to autobuy ingredients")
            return
        }
        root.coins -= cost
        var next = {}
        for (var k in root.ingredientStock)
            next[k] = root.ingredientStock[k]
        for (var m = 0; m < missing.length; ++m)
            next[missing[m]] = 1
        root.ingredientStock = next
        toast("Autobuy secured " + missing.length + " ingredients for " + plansModel.get(planIndex).name + " (-" + cost + " coins)")
    }

    function createPlan() {
        var nextSlots = root.planSlots.map(function(slots) { return slots.slice() })
        nextSlots.push(["Superior Blink", "Mythical Speed Potion", "Speed Anticellular Shield", "Powerful Portal Glue", "Super Glue Potion", "Legendary Speed Potion"])
        var nextAutobuy = root.planAutobuy.slice()
        nextAutobuy.push(false)
        plansModel.append({name: "New Plan " + (plansModel.count + 1), tag: "0 accounts", planColor: "#e5b64e"})
        root.planSlots = nextSlots
        root.planAutobuy = nextAutobuy
        root.activePlan = plansModel.count - 1
        root.savePlansNow()
        toast("New plan created")
    }

    function renamePlan(planIndex, newName) {
        if (newName === "" || planIndex < 0 || planIndex >= plansModel.count)
            return
        plansModel.setProperty(planIndex, "name", newName)
        root.savePlansNow()
        toast("Plan renamed to " + newName)
    }

    function deletePlan(planIndex) {
        if (plansModel.count <= 1) {
            toast("Cannot delete the last plan")
            return
        }
        if (planIndex < 0 || planIndex >= plansModel.count)
            return
        var nextSlots = root.planSlots.slice()
        nextSlots.splice(planIndex, 1)
        var nextAutobuy = root.planAutobuy.slice()
        nextAutobuy.splice(planIndex, 1)
        plansModel.remove(planIndex)
        root.planSlots = nextSlots
        root.planAutobuy = nextAutobuy
        if (root.activePlan >= planIndex)
            root.activePlan = Math.max(0, root.activePlan - 1)
        root.savePlansNow()
        toast("Plan deleted")
    }

    function addQw() {
        loginBridge.chooseQwFile()
    }

    // Abre el chest diario en TODAS las cuentas (do=news -> do=openchest)
    function openChest() {
        if (loginBridge.accounts.length === 0) {
            toast("No accounts loaded")
            return
        }
        var all = []
        for (var i = 0; i < loginBridge.accounts.length; ++i)
            all.push(i)
        toast("Opening chest on all " + all.length + " accounts...")
        loginBridge.openChestOnAccounts(all)
    }

    // Los rewards del endpoint pueden venir con title, type o solo sprite.
    // Resolver primero el nombre evita mostrar el sprite de otra pocion como
    // fallback cuando el servidor devuelve un identificador nuevo.
    function chestRewardCatalogItem(reward) {
        if (!reward)
            return null

        var candidates = [String(reward.sprite || ""), String(reward.title || "")]
        for (var c = 0; c < candidates.length; ++c) {
            var raw = candidates[c].trim().replace(/\.(png|jpg|jpeg)$/i, "")
            if (raw === "")
                continue

            for (var i = 0; i < root.shopItems.length; ++i) {
                var itemSprite = String(root.shopItems[i].img || "").replace(/\.(png|jpg|jpeg)$/i, "")
                if (itemSprite.toLowerCase() === raw.toLowerCase())
                    return root.shopItems[i]
            }

            // El endpoint puede devolver tile97, tile_97 o tile-97.
            var tileMatch = raw.match(/^tile[_-]?(\d+)$/i)
            if (tileMatch) {
                var itemId = Number(tileMatch[1])
                for (var j = 0; j < root.shopItems.length; ++j) {
                    if (Number(root.shopItems[j].id) === itemId)
                        return root.shopItems[j]
                }
            }
        }
        return null
    }

    function chestRewardName(reward) {
        if (!reward)
            return "REWARD"

        var title = String(reward.displayName || reward.title || "").trim()
        var type = String(reward.type || "").trim()
        var titleLower = title.toLowerCase()
        var typeLower = type.toLowerCase()
        if (titleLower === "coins" || titleLower === "coin" || typeLower === "coins" || typeLower === "coin")
            return "COINS"
        var catalogItem = root.chestRewardCatalogItem(reward)
        if (catalogItem)
            return catalogItem.name
        if (title !== "" && !/^tile[_-]?\d+$/i.test(title))
            return title.replace(/%20/g, " ")

        return type !== "" ? type : "REWARD"
    }

    function chestRewardImg(reward) {
        var name = root.chestRewardName(reward)
        if (name === "COINS")
            return ""

        var local = root.labImgForServerName(name)
        if (local !== "")
            return local

        var catalogItem = root.chestRewardCatalogItem(reward)
        if (catalogItem)
            return "qrc:/Utopia/assets/potions/sprites/" + catalogItem.img

        for (var i = 0; i < root.shopItems.length; ++i) {
            var item = root.shopItems[i]
            if (String(item.name).toLowerCase() === name.toLowerCase())
                return "qrc:/Utopia/assets/potions/sprites/" + item.img
        }

        var sprite = String(reward && reward.sprite || "").replace(/\.(png|jpg|jpeg)$/i, "")
        for (var j = 0; j < root.shopItems.length; ++j) {
            var itemSprite = String(root.shopItems[j].img || "").replace(/\.(png|jpg|jpeg)$/i, "")
            if (sprite !== "" && itemSprite === sprite)
                return "qrc:/Utopia/assets/potions/sprites/" + root.shopItems[j].img
        }
        return ""
    }

    function chestErrorText(error) {
        var value = String(error || "").toLowerCase()
        if (value.indexOf("no chest") >= 0 || value.indexOf("chest available") >= 0 || value.indexOf("no chest appeared") >= 0)
            return "NO HAY COFRES DISPONIBLES"
        return String(error || "ERROR AL ABRIR EL COFRE").toUpperCase()
    }

    function chestResultsOpen() {
        chestResultsDialog.open()
    }

    Component.onCompleted: {
        for (var i = 0; i < root.fullCatalog.length; ++i)
            shopModel.append(root.fullCatalog[i])

        var ingByPotion = {}
        for (var p = 0; p < shopModel.count; ++p) {
            var potionName = shopModel.get(p).name
            var ingCount = 2 + (p % 3)
            var ingList = []
            for (var g = 0; g < ingCount; ++g)
                ingList.push(root.ingredientPool[(p * 5 + g * 7) % root.ingredientPool.length])
            ingByPotion[potionName] = ingList
        }
        root.potionIngredients = ingByPotion

        var stock = {}
        for (var s = 0; s < root.ingredientPool.length; ++s)
            stock[root.ingredientPool[s]] = s % 4
        root.ingredientStock = stock

        // cargar planes guardados
        var saved = loginBridge.loadPlans()
        if (saved.length > 0) {
var loadedSlots = []
var loadedAutobuy = []
var loadedLoop = []
plansModel.clear()
for (var pi = 0; pi < saved.length; ++pi) {
    var pl = saved[pi]
    plansModel.append({name: pl.name, tag: "0 accounts", planColor: "#e5b64e"})
    loadedSlots.push(pl.slots)
    loadedAutobuy.push(pl.autobuy !== undefined ? pl.autobuy : false)
    loadedLoop.push(pl.loop !== undefined ? pl.loop : false)
}
root.planSlots = loadedSlots
root.planAutobuy = loadedAutobuy
root.planLoop = loadedLoop
} else {
root.planAutobuy = [true, false, false]
root.planLoop = [false, false, false]
}

// cargar asignaciones de cuentas a planes (persistidas en accounts.json)
var loadedPlans = []
for (var ap = 0; ap < loginBridge.accounts.length; ++ap) {
    var accData = loginBridge.accounts[ap]
    loadedPlans.push(accData.plan !== undefined ? accData.plan : "Unassigned")
}
root.accountPlans = loadedPlans

// scan automatico de labs al abrir
loginBridge.scanAllLabs()
}

    function savePlansNow() {
        var plans = []
        for (var pi = 0; pi < plansModel.count; ++pi) {
plans.push({name: plansModel.get(pi).name,
slots: root.planSlots[pi] || [],
autobuy: root.planAutobuy[pi] || false,
loop: root.planLoop[pi] || false})
        }
        loginBridge.savePlans(plans)
    }

    // Mapea los nombres del lab a IDs del inventory shop (para comprar)
    function inventoryIdForName(name) {
        var map = {
            "Mythical Speed Potion": 97,
            "Powerful Portal Glue": 1654,
            "Speed Shot": 2013,
            "Speed Anticellular Shield": 148,
            "Speed & Gravity Potion": 101,
            "Powerful Chainsaw": 320,
            "Portal Shield Armor": 145,
            "Legendary Speed Potion": 1646,
            "Legendary Gravity Potion": 101,
            "Legendary Blink": 104,
            "Super Glue Potion": 98,
            "Superior Portal Gun": 274,
            "Anticellular Armor": 147,
            "Superior Blink": 104,
            "Bubble Gun": 1494,
            "Antiviral Portal Gun": 145,
            "Superior Immunity Shield": 145,
            "Superior Gravity Blink": 101
        }
        return map[name] !== undefined ? map[name] : 0
    }

function autobuyPlan() {
    var names = []
    var slots = root.planSlots[root.activePlan] || []
    for (var s = 0; s < slots.length; ++s) {
        // El backend resuelve la receta y el ID real del inventario.
        // No filtrar con una tabla QML desactualizada: dejaba fuera
        // pociones válidas y hacía que AUTOBUY pareciera fallar.
        if (slots[s] && slots[s] !== "")
            names.push(slots[s])
    }
    if (names.length === 0) {
        toast("No buyable potions in plan")
        return
    }
    root.planActionQueue = []
    for (var i = 0; i < loginBridge.accounts.length; ++i) {
        if (root.assignedToActivePlan(i))
            root.planActionQueue.push({index: i, names: names.slice()})
    }
    if (root.planActionQueue.length === 0) {
        toast("No accounts assigned to this plan")
        return
    }
    root.planActionNames = names
    root.planActionIsAutobuy = true
    toast("AUTOBUY on " + root.planActionQueue.length + " assigned accounts...")
}

function craftPlanAll() {
    var names = root.planSlots[root.activePlan] || []
    if (names.length === 0) {
        toast("Plan is empty")
        return
    }
    root.planActionQueue = []
    for (var i = 0; i < loginBridge.accounts.length; ++i) {
        if (root.assignedToActivePlan(i))
            root.planActionQueue.push({index: i, names: names.slice()})
    }
    if (root.planActionQueue.length === 0) {
        toast("No accounts assigned to this plan")
        return
    }
    root.planActionNames = names
    root.planActionIsAutobuy = false
    toast("CRAFT on " + root.planActionQueue.length + " assigned accounts...")
}

    function toggleBuyAccount(index) {
        var next = root.buySelection.slice()
        next[index] = !next[index]
        root.buySelection = next
    }

function buyItemOnSelected(itemId, packs) {
    var idxs = []
    for (var i = 0; i < loginBridge.accounts.length; ++i) {
        if (root.buySelection[i])
            idxs.push(i)
    }
    if (idxs.length === 0) {
        toast("Select at least one account to buy")
        return
    }
    loginBridge.buyOnAccounts(idxs, itemId, packs === undefined ? 1 : packs)
}

    Timer { id: toastTimer; interval: 2400; onTriggered: root.showToast = false }

    Connections {
        target: loginBridge
        function onChestResultsChanged() {
            if (!chestResultsDialog.visible)
                root.chestResultsOpen()
        }
    }

    // Contador en vivo: muestra el tiempo restante decreciendo segundo a segundo
    Connections {
        target: loginBridge
        function onCoinsChanged() {
            root.coins = loginBridge.coins
        }
        function onAllLabsChanged() {
            var labs = loginBridge.allLabs
            var built = []
            for (var ai = 0; ai < labs.length; ++ai) {
                var acc = labs[ai]
                var slots = []
                var raw = acc.slots !== undefined ? acc.slots : []
                for (var si = 0; si < raw.length; ++si) {
                    var sl = raw[si]
                slots.push({index: sl.index, status: sl.status, name: sl.name,
                time: sl.time, price: sl.price, qty: sl.qty !== undefined ? sl.qty : 0,
                baseTime: sl.time, baseTick: root.labTickCount})
                }
                built.push({name: acc.name, deviceId: acc.deviceId, ok: acc.ok, error: acc.error, slots: slots})
            }
            root.liveLabs = built

            // limpiar el registro de slots ya re-crafteados: cuando el scan nuevo
            // muestra un slot distinto (re-crafteado o recogido), permitir que el
            // loop pueda disparar de nuevo en el futuro
            var doneKeysClean = root.loopDoneKeys || {}
            if (doneKeysClean) {
                var stillKeys = {}
                for (var kai = 0; kai < built.length; ++kai) {
                    var kacc = built[kai]
                    var kslots = kacc.slots || []
                    for (var ksi = 0; ksi < kslots.length; ++ksi) {
                        var ks = kslots[ksi]
                        var kk = kai + "_" + ks.index
                        // conservar solo slots que siguen terminados (display con poción)
                        if (ks.status !== "crafting" && ks.name && doneKeysClean[kk] !== undefined)
                            stillKeys[kk] = doneKeysClean[kk]
                    }
                }
                root.loopDoneKeys = stillKeys
            }
        }
    }

Timer {
    id: labTick
    interval: 1000
    running: true
    repeat: true
    onTriggered: {
        // cambia el tick -> fuerza la reevaluacion de los bindings del tiempo
        root.labTickCount++

        // (sin re-scan periodico: el scan inicial es suficiente. El loop detecta
        // terminaciones con el contador local y tras cada craft solo se actualiza
        // la cuenta que crafteo, para no romper las sesiones del juego abierto)

        // LOOP: vigilar TODOS los planes con loop activo, no solo el plan activo de la UI.
        // Detecta slots que terminaron (crafting -> ready/free) y re-craftea en las cuentas asignadas.
        if (!loginBridge.busy && root.planActionQueue.length === 0) {
            var labs = root.liveLabs
            var prev = root.loopPrevSlots || {}
            if (labs.length === 0) {
                loginBridge.logDebug("LOOP: liveLabs vacio")
                return
            }
            var cur = {}
            // registrar estado actual de TODAS las cuentas
            for (var ai = 0; ai < labs.length; ++ai) {
                var acc = labs[ai]
                var slots = acc.slots || []
                for (var si = 0; si < slots.length; ++si) {
                    var s = slots[si]
                    var key = ai + "_" + s.index
                    cur[key] = s.status
                }
            }
            root.loopPrevSlots = cur

            // buscar el primer plan con loop activo que tenga cuentas asignadas con slots terminados
            for (var pi = 0; pi < plansModel.count; ++pi) {
                if (!root.planLoop[pi])
                    continue
                var planName = plansModel.get(pi).name
                var finished = false
                var finishedNamesByAccount = {}
                var pendingKeys = {}
                for (var fi = 0; fi < labs.length; ++fi) {
                    if (root.accountPlans[fi] !== planName)
                        continue
                    var fslots = labs[fi].slots || []
                    for (var fsi = 0; fsi < fslots.length; ++fsi) {
                        var fs = fslots[fsi]
                        var fkey = fi + "_" + fs.index
                        var slotFinished = false
                        // transicion en vivo: estaba crafting y ya no
                        if (prev[fkey] === "crafting" && fs.status !== "crafting")
                            slotFinished = true
                        // slot con poción terminada sin recoger (server: craft='ready'
                        // -> status='display' con name). Dispara SIEMPRE que esté listo
                        // y no haya sido procesado: cubre slots ready desde el arranque
                        // (el check de prev fallaba porque ya venian en 'display').
                        var doneKeys = root.loopDoneKeys || {}
                        if (fs.name && fs.name !== "" && fs.status !== "crafting" && !doneKeys[fkey]) {
                            loginBridge.logDebug("LOOP: slot " + fkey + " listo [" + fs.name + "] status=" + fs.status)
                            slotFinished = true
                        }
                        // contador local llego a 0 (sin esperar el scan): la pocion termino
                        if (!slotFinished && fs.status === "crafting" && root.slotRemaining(fs) <= 0)
                            slotFinished = true
                        if (slotFinished) {
                            // solo disparar una vez por slot: si ya fue re-crafteado, el
                            // estado del server cambiara en el proximo scan; evitamos spam
                            var doneKeys2 = root.loopDoneKeys || {}
                            if (doneKeys2[fkey])
                                continue
                            if (!root.loopDoneKeys)
                                root.loopDoneKeys = {}
                            root.loopDoneKeys[fkey] = root.labTickCount
                            finished = true
                            if (!finishedNamesByAccount[fi])
                                finishedNamesByAccount[fi] = []
                            // la poción terminada (nombre del server "3x X" -> "X").
                            // SIN deduplicar: si 2 slots terminaron la misma pocion,
                            // se necesita craftear 2 copias (1 por slot liberado)
                            var cleanName = String(fs.name || "").replace(/^\d+x\s*/, "").trim()
                            finishedNamesByAccount[fi].push(cleanName)
                        }
                    }
                }
                // SI no hay slots terminados: buscar TODAS las cuentas con slots
                // LIBRES (ready sin poción) y llenarlas con las pociones del plan.
                // Se encolan juntas para llenarse en un solo ciclo.
                if (!finished) {
                    var planSlotsDef = root.planSlots[pi] || []
                    var fillQueue = []
                    for (var fai = 0; fai < labs.length; ++fai) {
                        if (root.accountPlans[fai] !== planName)
                            continue
                        var facc = labs[fai]
                        var fslots2 = facc.slots || []
                        var freeSlots = 0
                        var craftingHere = {}
                        for (var fsi2 = 0; fsi2 < fslots2.length; ++fsi2) {
                            var fs2 = fslots2[fsi2]
                            if (fs2.status === "crafting" && fs2.name)
                                craftingHere[String(fs2.name).replace(/^\d+x\s*/, "").trim()] = true
                            else if (fs2.status === "ready" && !fs2.name)
                                freeSlots++
                        }
                        if (freeSlots <= 0)
                            continue
                        // pociones del plan para llenar los slots libres
                        var toCraft = []
                        for (var ps = 0; ps < planSlotsDef.length && toCraft.length < freeSlots; ++ps) {
                            if (!craftingHere[planSlotsDef[ps]])
                                toCraft.push(planSlotsDef[ps])
                        }
                        if (toCraft.length < freeSlots && planSlotsDef.length > 0) {
                            var fillIdx = 0
                            while (toCraft.length < freeSlots) {
                                toCraft.push(planSlotsDef[fillIdx % planSlotsDef.length])
                                fillIdx++
                            }
                        }
                        if (toCraft.length > 0) {
                            fillQueue.push({index: fai, names: toCraft.slice()})
                        }
                    }
                    if (fillQueue.length > 0) {
                        root.planActionNames = []
                        root.planActionIsAutobuy = root.planAutobuy[pi]
                        root.planActionQueue = fillQueue
                        toast("LOOP [" + planName + "]: filling " + fillQueue.length + " account(s) with free slots")
                        break
                    }
                    continue
                }

                // re-craftear SOLO en la cuenta cuyo slot termino (no en todas):
                // la poción terminada se recoge (PICK) y se vuelve a craftear en ese mismo slot
                var finishedAccountIndexes = Object.keys(finishedNamesByAccount)
                if (finishedAccountIndexes.length > 0) {
                    root.planActionNames = []
                    root.planActionIsAutobuy = root.planAutobuy[pi]
                    var q = []
                    for (var qi = 0; qi < finishedAccountIndexes.length; ++qi) {
                        var accountIndex = Number(finishedAccountIndexes[qi])
                        q.push({index: accountIndex, names: finishedNamesByAccount[accountIndex]})
                    }
                    if (q.length > 0) {
                        root.planActionQueue = q
                        loginBridge.logDebug("LOOP [" + planName + "]: re-crafting on " + q.length + " account(s)")
                        toast("LOOP [" + planName + "]: re-crafting on " + q.length + " account(s)")
                    }
                }
                break
            }
        } else {
            // mantener registro aunque haya loop apagado/busy (para no disparar falso positivo al encenderlo)
            var c2 = {}
            var labs2 = root.liveLabs
            for (var b = 0; b < labs2.length; ++b) {
                var a2 = labs2[b]
                var sl2 = a2.slots || []
                for (var s2i = 0; s2i < sl2.length; ++s2i) {
                    var s2 = sl2[s2i]
                    c2[b + "_" + s2.index] = s2.status
                }
            }
            root.loopPrevSlots = c2
        }
    }
}

// Encadena autobuy/craft sobre las cuentas asignadas: cuando el bridge
// termina una cuenta (busy=false), lanza la siguiente de la cola.
Timer {
    id: planChainTimer
    interval: 400
    running: true
    repeat: true
    onTriggered: {
        if (root.planActionQueue.length > 0 && !loginBridge.busy) {
            var next = root.planActionQueue.shift()
            var nextIndex = next && next.index !== undefined ? next.index : next
            var nextNames = next && next.names !== undefined ? next.names : root.planActionNames
            if (nextNames.length > 0) {
                if (root.planActionIsAutobuy)
                    loginBridge.autobuy(nextIndex, nextNames)
                else
                    loginBridge.craftPlan(nextIndex, nextNames)
            }
        } else if (root.planActionQueue.length === 0 && root.planActionNames.length > 0 && !loginBridge.busy) {
            root.planActionNames = []
            root.planActionIsAutobuy = false
        }
    }
}

    // Formatea el tiempo restante de un slot crafteando (h:m:s, decreciente en vivo)
    function formatRemaining(slot) {
        if (slot.status !== "crafting")
            return ""
        var elapsed = root.labTickCount - slot.baseTick
        var remaining = Math.max(0, slot.baseTime - elapsed)
        var h = Math.floor(remaining / 3600)
        var m = Math.floor((remaining % 3600) / 60)
        var s = remaining % 60
        return h + "h " + (m < 10 ? "0" : "") + m + "m " + (s < 10 ? "0" : "") + s + "s"
    }

    // Segundos restantes reales del slot (0 si ya termino)
    function slotRemaining(slot) {
        if (!slot || slot.status !== "crafting")
            return 0
        var elapsed = root.labTickCount - slot.baseTick
        return Math.max(0, slot.baseTime - elapsed)
    }

    // true cuando el contador del slot llego a 0 (termino de craftear)
    function slotIsDone(slot) {
        return slot && slot.status === "crafting" && root.slotRemaining(slot) <= 0
    }

    component LabelText: Label {
        color: colors.text
        font.family: "Bahnschrift"
        font.pixelSize: 12
        elide: Text.ElideRight
    }

    component SmallCaption: Label {
        color: colors.muted
        font.family: "Bahnschrift"
        font.pixelSize: 11
        font.weight: Font.DemiBold
        font.letterSpacing: 0.7
        elide: Text.ElideRight
    }

    component Panel: Rectangle {
        color: colors.surface
        border.color: colors.border
        border.width: 1
        radius: 8
        clip: true
        Rectangle {
            anchors.left: parent.left
            anchors.top: parent.top
            width: 44
            height: 2
            color: colors.teal
            opacity: 0.72
        }
        Rectangle {
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            width: 24
            height: 2
            color: colors.purple
            opacity: 0.60
        }
    }

    component StatusPill: Rectangle {
        id: pill
        property string value: "OPEN"
        property color accent: colors.teal
        implicitWidth: pillLabel.implicitWidth + 22
        implicitHeight: 23
        radius: 12
        color: Qt.rgba(accent.r, accent.g, accent.b, 0.10)
        border.color: Qt.rgba(accent.r, accent.g, accent.b, 0.82)
        border.width: 1
        LabelText { id: pillLabel; anchors.centerIn: parent; text: pill.value; color: pill.accent; font.pixelSize: 9; font.weight: Font.Black }
    }

    component ActionButton: Button {
        id: action
        implicitHeight: 34
        leftPadding: 12
        rightPadding: 12
        contentItem: LabelText { text: action.text; color: "#061018"; horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter; font.weight: Font.Black; font.pixelSize: 10; font.letterSpacing: 0.4 }
        background: Rectangle { radius: 6; color: action.down ? "#9f7029" : (action.hovered ? "#ffda73" : colors.gold); border.color: action.hovered ? "#fff1b0" : "#d9ad42"; border.width: 1 }
    }

    component GhostButton: Button {
        id: ghost
        implicitHeight: 32
        leftPadding: 12
        rightPadding: 12
        contentItem: LabelText { text: ghost.text; color: ghost.hovered ? colors.teal : colors.muted; horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter; font.weight: Font.Black; font.pixelSize: 10 }
        background: Rectangle { radius: 6; color: ghost.hovered ? "#17384a" : colors.surface; border.color: ghost.hovered ? colors.teal : colors.border; border.width: 1 }
    }

    component PotionSelector: ComboBox {
        id: selector
        property int slotIndex: -1
        model: labModel
        textRole: "name"
        implicitHeight: 34
        leftPadding: 8
        rightPadding: 28
        font.family: "Bahnschrift"
        font.pixelSize: 10

        // Sincroniza el indice con el slot del plan activo (sin binding declarativo,
        // asi las asignaciones internas del ComboBox no lo rompen)
        function syncIndex() {
            selector.currentIndex = root.potionIndexForName((root.planSlots[root.activePlan] || [])[slotIndex] || "")
        }
        Component.onCompleted: syncIndex()
        Connections {
            target: root
            function onPlanSlotsChanged() { selector.syncIndex() }
            function onActivePlanChanged() { selector.syncIndex() }
        }
        onActivated: root.setPlanSlot(slotIndex, currentText)

        contentItem: RowLayout {
            anchors.fill: parent
            anchors.leftMargin: selector.leftPadding
            anchors.rightMargin: selector.rightPadding
            spacing: 7
            Image {
                Layout.preferredWidth: 24
                Layout.preferredHeight: 24
                visible: selector.currentIndex >= 0 && selector.currentIndex < labModel.count
                source: visible ? "qrc:/Utopia/assets/potions/lab_sprites/" + labModel.get(selector.currentIndex).img : ""
                fillMode: Image.PreserveAspectFit
                smooth: true
                mipmap: true
            }
            LabelText {
                Layout.fillWidth: true
                text: selector.currentText
                color: colors.text
                font.pixelSize: 10
                font.weight: Font.Black
                elide: Text.ElideRight
            }
        }

        indicator: LabelText {
            anchors.right: parent.right
            anchors.rightMargin: 9
            anchors.verticalCenter: parent.verticalCenter
            text: "▾"
            color: selector.popup.visible ? colors.teal : colors.muted
            font.pixelSize: 13
            font.weight: Font.Black
        }

        background: Rectangle {
            radius: 6
            color: selector.popup.visible ? "#173b4d" : "#0a1826"
            border.color: selector.visualFocus || selector.popup.visible ? colors.teal : colors.border
            border.width: 1
        }

        delegate: ItemDelegate {
            width: selector.width - 2
            height: 40
            highlighted: selector.highlightedIndex === index
            contentItem: RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 8
                anchors.rightMargin: 8
                spacing: 8
                Image {
                    Layout.preferredWidth: 27
                    Layout.preferredHeight: 27
                    source: "qrc:/Utopia/assets/potions/lab_sprites/" + model.img
                    fillMode: Image.PreserveAspectFit
                    smooth: true
                    mipmap: true
                }
                LabelText {
                    Layout.fillWidth: true
                    text: model.name
                    color: highlighted ? colors.text : colors.muted
                    font.pixelSize: 11
                    font.weight: highlighted ? Font.Black : Font.DemiBold
                    elide: Text.ElideRight
                }
            }
            background: Rectangle {
                radius: 4
                color: highlighted ? "#174355" : "#0b1a28"
                border.color: highlighted ? colors.teal : "transparent"
                border.width: 1
            }
            onClicked: {
                // setear indice + activar: el ComboBox actualiza currentIndex/currentText
                // y dispara onActivated (que guarda en el plan)
                selector.currentIndex = index
                selector.activated(index)
                selector.popup.close()
            }
        }

        popup: Popup {
            y: selector.height + 4
            width: selector.width
            padding: 4
            contentItem: ListView {
                clip: true
                implicitHeight: Math.min(contentHeight, 320)
                model: selector.popup.visible ? selector.delegateModel : null
                currentIndex: selector.highlightedIndex
                ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }
            }
            background: Rectangle {
                color: "#08131f"
                radius: 7
                border.color: colors.teal
                border.width: 1
            }
        }

        // El multiplicador vive en accounts.json y no cambia el payload del
        // ultimo scan. Forzar la reconstruccion de liveLabs hace que todos
        // los bindings (x1/x2/x3 y cantidades) se recalculen de inmediato.
        function onAccountsChanged() {
            var refreshed = []
            for (var ai = 0; ai < root.liveLabs.length; ++ai) {
                var lab = root.liveLabs[ai]
                refreshed.push({name: lab.name, deviceId: lab.deviceId, ok: lab.ok,
                                error: lab.error, slots: lab.slots})
            }
            root.liveLabs = refreshed
        }
    }

    component LabMultiplierSelector: ComboBox {
        id: multiplierSelector
        property int accountIndex: -1
        model: ["x1 LAB", "x2 LAB", "x3 LAB"]
        currentIndex: Math.max(0, root.accountLabMultiplier(accountIndex) - 1)
        implicitWidth: 64
        implicitHeight: 26
        font.family: "Bahnschrift"
        font.pixelSize: 9
        leftPadding: 7
        rightPadding: 18
        onActivated: root.setAccountLabMultiplier(multiplierSelector.accountIndex, currentIndex + 1)

        contentItem: LabelText {
            text: multiplierSelector.currentText
            color: multiplierSelector.currentIndex > 0 ? colors.gold : colors.muted
            font.pixelSize: 9
            font.weight: Font.Black
            verticalAlignment: Text.AlignVCenter
            elide: Text.ElideRight
        }
        indicator: LabelText {
            anchors.right: parent.right
            anchors.rightMargin: 6
            anchors.verticalCenter: parent.verticalCenter
            text: "▾"
            color: multiplierSelector.popup.visible ? colors.teal : colors.muted
            font.pixelSize: 11
        }
        background: Rectangle {
            radius: 5
            color: multiplierSelector.popup.visible ? "#173b4d" : "#0a1826"
            border.color: multiplierSelector.popup.visible ? colors.teal : colors.borderSoft
            border.width: 1
        }
        delegate: ItemDelegate {
            width: multiplierSelector.width - 2
            height: 30
            highlighted: multiplierSelector.highlightedIndex === index
            contentItem: LabelText {
                text: modelData
                color: highlighted ? colors.text : colors.muted
                font.pixelSize: 10
                font.weight: highlighted ? Font.Black : Font.DemiBold
                verticalAlignment: Text.AlignVCenter
                leftPadding: 8
            }
            background: Rectangle {
                radius: 4
                color: highlighted ? "#174355" : "#0b1a28"
                border.color: highlighted ? colors.teal : "transparent"
            }
            onClicked: {
                multiplierSelector.currentIndex = index
                multiplierSelector.activated(index)
                multiplierSelector.popup.close()
            }
        }
        popup: Popup {
            y: multiplierSelector.height + 4
            width: multiplierSelector.width
            padding: 4
            contentItem: ListView {
                implicitHeight: 3 * 30
                model: multiplierSelector.popup.visible ? multiplierSelector.delegateModel : null
            }
            background: Rectangle {
                color: "#08131f"
                radius: 6
                border.color: colors.teal
                border.width: 1
            }
        }
    }

    component AutobuyToggle: Rectangle {
        id: autobuyToggle
        property bool active: false
        property string label: "AUTOBUY"
        signal toggled()
        implicitWidth: 96
        implicitHeight: 26
        radius: 13
        color: active ? "#173139" : colors.surface2
        border.color: active ? colors.teal : colors.border
        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 9
            anchors.rightMargin: 9
            spacing: 6
            Rectangle { width: 12; height: 12; radius: 6; color: autobuyToggle.active ? colors.teal : colors.muted }
            LabelText { text: autobuyToggle.label; color: autobuyToggle.active ? colors.teal : colors.muted; font.pixelSize: 9; font.weight: Font.Black }
        }
        MouseArea { anchors.fill: parent; onClicked: autobuyToggle.toggled() }
    }

    Rectangle {
        anchors.fill: parent
        color: colors.canvas

        Image { anchors.fill: parent; source: "qrc:/Utopia/assets/visuals/rapper-cross.png"; fillMode: Image.PreserveAspectCrop; horizontalAlignment: Image.AlignRight; opacity: 0.10; z: 0 }
        Rectangle {
            anchors.fill: parent
            gradient: Gradient {
                GradientStop { position: 0.0; color: "#e6040810" }
                GradientStop { position: 0.42; color: "#d9081420" }
                GradientStop { position: 1.0; color: "#f0020710" }
            }
            z: 1
        }

        RowLayout {
            anchors.fill: parent
            spacing: 0
            z: 2

            Rectangle {
                Layout.preferredWidth: 236
                Layout.fillHeight: true
                color: colors.surface
                border.color: colors.borderSoft
                border.width: 1

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 18
                    spacing: 0

                    RowLayout { Layout.fillWidth: true; spacing: 8; LabelText { text: "MITOSIS"; color: colors.gold; font.pixelSize: 20; font.bold: true } LabelText { text: "UTOPIA"; font.pixelSize: 18; font.weight: Font.Black; font.letterSpacing: 2.2 } }
                    LabelText { text: "POTION CARTEL // LAB 09"; color: colors.purple; font.pixelSize: 8; font.letterSpacing: 1.2; Layout.topMargin: 4 }
                    Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: colors.border; opacity: 0.75; Layout.topMargin: 10 }
                    Item { Layout.preferredHeight: 26 }

                    Panel {
                        Layout.fillWidth: true
                        Layout.preferredHeight: 132
                        clip: true
                        Image { anchors.fill: parent; source: "qrc:/Utopia/assets/visuals/rapper-close.png"; fillMode: Image.PreserveAspectCrop; opacity: 0.46 }
                        Rectangle { anchors.fill: parent; color: "#b6071015" }
                        ColumnLayout { anchors.fill: parent; anchors.margins: 12; spacing: 4; Item { Layout.fillHeight: true } LabelText { text: "PRIVATE MIX"; color: colors.gold; font.pixelSize: 9; font.weight: Font.Black; font.letterSpacing: 1.3 } LabelText { text: "UTOPIA AFTER HOURS"; font.pixelSize: 12; font.weight: Font.Black } SmallCaption { text: "Brew clean. Move quiet."; color: colors.text } }
                    }

                    Item { Layout.preferredHeight: 26 }
                    Repeater {
                        model: ["Laboratory", "Inventory", "Craft History", "Shop"]
                        delegate: Rectangle {
                            Layout.fillWidth: true
                            Layout.preferredHeight: 42
                            radius: 4
                            color: root.section === index ? "#123342" : "transparent"
                            border.color: root.section === index ? colors.teal : "transparent"
                            border.width: root.section === index ? 1 : 0
                            RowLayout { anchors.fill: parent; anchors.leftMargin: 12; anchors.rightMargin: 10; spacing: 10; LabelText { text: ["+", "V", "H", "S"][index]; color: root.section === index ? colors.gold : colors.muted; font.pixelSize: 12; Layout.preferredWidth: 20 } LabelText { text: modelData; color: root.section === index ? colors.text : colors.muted; font.weight: root.section === index ? Font.Black : Font.Normal; Layout.fillWidth: true } Rectangle { visible: root.section === index; width: 4; height: 4; radius: 2; color: colors.teal } }
                            MouseArea { anchors.fill: parent; onClicked: root.section = index }
                        }
                    }

                    Item { Layout.fillHeight: true }
                    Panel { Layout.fillWidth: true; Layout.preferredHeight: 100; color: colors.surface2; ColumnLayout { anchors.fill: parent; anchors.margins: 12; spacing: 7; RowLayout { Layout.fillWidth: true; SmallCaption { text: "LAB STATUS"; color: colors.muted; Layout.fillWidth: true } StatusPill { value: "STABLE"; accent: colors.teal } } LabelText { text: "3 active brews"; font.pixelSize: 11 } RowLayout { Layout.fillWidth: true; Rectangle { width: 6; height: 6; radius: 3; color: colors.gold } LabelText { text: "Plans synced"; color: colors.gold; font.pixelSize: 10 } Item { Layout.fillWidth: true } SmallCaption { text: "v1.1.0" } } } }
                    Item { Layout.preferredHeight: 14 }
                    Panel { Layout.fillWidth: true; color: colors.surface2; ColumnLayout { anchors.fill: parent; anchors.margins: 12; spacing: 6; RowLayout { Layout.fillWidth: true; SmallCaption { text: "ACCOUNT // HTTP LOGIN"; color: colors.purple; Layout.fillWidth: true } StatusPill { value: loginBridge.loggedIn ? "ONLINE" : "OFFLINE"; accent: loginBridge.loggedIn ? colors.teal : colors.danger } } LabelText { text: loginBridge.loggedIn ? loginBridge.accountName : "Not logged in"; font.pixelSize: 11; font.weight: Font.Black; elide: Text.ElideRight; Layout.fillWidth: true } RowLayout { Layout.fillWidth: true; spacing: 6; ActionButton { text: loginBridge.loggedIn ? "REFRESH" : "LOGIN"; Layout.fillWidth: true; enabled: !loginBridge.busy; onClicked: loginBridge.loggedIn ? loginBridge.refreshInventory() : loginBridge.login() } } } }
                    Item { Layout.preferredHeight: 16 }
                    LabelText { text: "UTOPIA LABS  //  2026"; color: colors.faint; font.pixelSize: 9; font.letterSpacing: 0.7 }
                }
            }

            ColumnLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                spacing: 0

                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 78
                    color: colors.surface
                    border.color: colors.borderSoft
                    Rectangle { anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom; height: 1; color: colors.border }
                    Rectangle { anchors.left: parent.left; anchors.bottom: parent.bottom; width: 120; height: 2; color: colors.teal; opacity: 0.85 }
                    RowLayout { anchors.fill: parent; anchors.leftMargin: 26; anchors.rightMargin: 26; spacing: 14; ColumnLayout { Layout.fillWidth: true; spacing: 2; LabelText { text: section === 0 ? "Laboratory Plans" : (section === 1 ? "Inventory" : (section === 2 ? "Craft History" : "Shop")); font.pixelSize: 20; font.weight: Font.Black; font.letterSpacing: 0.8 } SmallCaption { text: section === 0 ? "Assign six-slot potion plans to selected accounts" : (section === 1 ? "Your secured Utopia stash" : (section === 2 ? "Per-account potion production history" : "Buy potions and manage accounts")); color: colors.muted; elide: Text.ElideRight } } SmallCaption { text: "NODE 09 // SECURE"; color: colors.faint; font.pixelSize: 9; font.letterSpacing: 1.0 } StatusPill { value: "ONLINE"; accent: colors.teal } Panel { Layout.preferredWidth: 120; Layout.preferredHeight: 36; color: colors.surface2; RowLayout { anchors.fill: parent; anchors.margins: 10; LabelText { text: "COINS"; color: colors.muted; font.pixelSize: 9; Layout.fillWidth: true } LabelText { text: root.coins.toString(); color: colors.gold; font.pixelSize: 13; font.weight: Font.Black } } } ActionButton { visible: section === 0; text: "RENAME"; onClicked: { planRenameIndex = root.activePlan; planRenameDialog.open() } } ActionButton { visible: section === 0; text: "DELETE"; onClicked: root.deletePlan(root.activePlan) } }
                }

                RowLayout { Layout.fillWidth: true; Layout.preferredHeight: 82; Layout.minimumHeight: 82; Layout.maximumHeight: 82; Layout.leftMargin: 26; Layout.rightMargin: 26; spacing: 0; Repeater { model: [{t:"IN STOCK",v:"24",c:colors.teal},{t:"ACTIVE BREWS",v:"3",c:colors.purple},{t:"RECIPES",v:"54",c:colors.gold},{t:"BLACKLISTED",v:"0",c:colors.danger}]; delegate: Item { Layout.fillWidth: true; Layout.fillHeight: true; Rectangle { anchors.right: parent.right; anchors.top: parent.top; anchors.bottom: parent.bottom; width: 1; color: colors.borderSoft; visible: index < 3 } ColumnLayout { anchors.fill: parent; anchors.leftMargin: 18; anchors.topMargin: 18; spacing: 4; SmallCaption { text: modelData.t } LabelText { text: modelData.v; color: modelData.c; font.pixelSize: 20; font.weight: Font.Black } } } } }

                StackLayout {
                    currentIndex: root.section
                    Layout.fillWidth: true
                    Layout.fillHeight: true

                    // Laboratory: plans, six potion slots and account assignment
                    ColumnLayout {
                        Layout.margins: 16
                        spacing: 8
                        RowLayout {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            spacing: 10
                        Panel {
                            Layout.preferredWidth: 190
                            Layout.minimumWidth: 170
                            Layout.fillHeight: true
                            ColumnLayout {
                                anchors.fill: parent
                                anchors.margins: 14
                                spacing: 10
                                RowLayout { Layout.fillWidth: true; LabelText { text: "Plans"; font.pixelSize: 17; font.weight: Font.Black; Layout.fillWidth: true } GhostButton { text: "+"; Layout.preferredWidth: 32; onClicked: root.createPlan() } }
                                SmallCaption { text: "SELECT A PLAN TO EDIT"; color: colors.purple }
                                ListView {
                                    Layout.fillWidth: true
                                    Layout.fillHeight: true
                                    clip: true
                                    spacing: 6
                                    model: plansModel
                                    delegate: Panel {
                                        width: ListView.view.width
                                        height: 62
                                        color: root.activePlan === index ? "#1a3035" : colors.surface2
                                        border.color: root.activePlan === index ? colors.teal : colors.borderSoft
                                        MouseArea { anchors.fill: parent; onClicked: root.activePlan = index }
                                        ColumnLayout { anchors.fill: parent; anchors.margins: 10; spacing: 3; RowLayout { Layout.fillWidth: true; LabelText { text: model.name; font.pixelSize: 13; font.weight: Font.Black; Layout.fillWidth: true; elide: Text.ElideRight } LabelText { text: root.planAutobuy[index] ? "AUTOBUY" : ""; color: colors.teal; font.pixelSize: 10; font.weight: Font.Black } Rectangle { width: 7; height: 7; radius: 4; color: model.planColor } } RowLayout { Layout.fillWidth: true; SmallCaption { text: root.assignedCount(model.name) + " assigned"; color: root.activePlan === index ? colors.teal : colors.muted; Layout.fillWidth: true } LabelText { text: root.planMissingCount(index) === 0 ? "READY" : root.planMissingCount(index) + " MISSING"; color: root.planMissingCount(index) === 0 ? colors.teal : colors.gold; font.pixelSize: 10; font.weight: Font.Black } } }
                                    }
                                }
                                Item { Layout.fillHeight: true; Layout.preferredHeight: 0 }
                                SmallCaption { text: "50 accounts in scope"; color: colors.gold }
                            }
                        }
                        Panel {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            Layout.preferredWidth: 500
                            Layout.minimumWidth: 200
                            ColumnLayout {
                                anchors.fill: parent
                                anchors.margins: 14
                                spacing: 9
                                RowLayout { Layout.fillWidth: true; LabelText { text: "Plan // " + root.activePlanName(); font.pixelSize: 17; font.weight: Font.Black; Layout.fillWidth: true } StatusPill { value: "6 SLOTS"; accent: colors.purple } }
                                SmallCaption { text: "Choose the potion loadout every assigned account will run." }
                                RowLayout { Layout.fillWidth: true; SmallCaption { text: root.planMissingCount(root.activePlan) === 0 ? "All ingredients in stock" : root.planMissingCount(root.activePlan) + " ingredients missing"; color: root.planMissingCount(root.activePlan) === 0 ? colors.teal : colors.gold; Layout.fillWidth: true } AutobuyToggle { active: root.planAutobuy[root.activePlan]; label: "AUTOBUY"; onToggled: root.toggleAutobuy(root.activePlan) } AutobuyToggle { active: root.planLoop[root.activePlan]; label: "LOOP"; onToggled: root.toggleLoop(root.activePlan) } }
                                GridLayout {
                                    Layout.fillWidth: true
                                    Layout.fillHeight: true
                                    columns: 2
                                    columnSpacing: 8
                                    rowSpacing: 8
                                    Repeater {
                                        model: 6
                                        delegate: Panel {
                                            Layout.fillWidth: true
                                            Layout.fillHeight: true
                                            Layout.preferredHeight: 158
                                            Layout.minimumHeight: 140
                                            color: colors.surface2
                                            ColumnLayout { anchors.fill: parent; anchors.margins: 10; spacing: 6; RowLayout { Layout.fillWidth: true; SmallCaption { text: "SLOT " + (index + 1).toString().padStart(2, "0"); color: colors.gold; Layout.fillWidth: true } LabelText { text: "ARMED"; color: colors.teal; font.pixelSize: 8; font.weight: Font.Black } } Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 80; color: "#081722"; radius: 6; border.color: colors.borderSoft; clip: true; Image { anchors.centerIn: parent; width: 96; height: 76; source: root.slotPotionImgForName(slotSelector.currentText || (root.planSlots[root.activePlan] || [])[index] || "Mythical Speed Potion"); fillMode: Image.PreserveAspectFit; smooth: true; mipmap: true; opacity: 0.95 } } LabelText { text: (root.planSlots[root.activePlan] || [])[index] || ""; color: colors.text; font.pixelSize: 10; font.weight: Font.Black; Layout.fillWidth: true } PotionSelector { id: slotSelector; slotIndex: index; Layout.fillWidth: true } SmallCaption { text: "PLAN-BOUND POTION"; color: colors.faint } }
                                        }
                                    }
                                }
                                 RowLayout { Layout.fillWidth: true; SmallCaption { text: root.assignedCount(root.activePlanName()) + " accounts will receive this loadout"; color: colors.teal; Layout.fillWidth: true } ActionButton { text: "CRAFT"; enabled: !loginBridge.busy; onClicked: root.planAutobuy[root.activePlan] ? root.autobuyPlan() : root.craftPlanAll() } ActionButton { text: "REFRESH LAB"; enabled: !loginBridge.busy; onClicked: loginBridge.refreshLaboratory() } }
                                Panel { Layout.fillWidth: true; color: colors.surface2; ColumnLayout { anchors.fill: parent; anchors.margins: 10; spacing: 6; RowLayout { Layout.fillWidth: true; SmallCaption { text: "LIVE LABORATORY"; color: colors.gold; Layout.fillWidth: true } StatusPill { value: loginBridge.labSlots.length === 0 ? "OFFLINE" : "SYNCED"; accent: loginBridge.labSlots.length === 0 ? colors.muted : colors.teal } } Repeater { model: loginBridge.labSlots; delegate: Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 30; radius: 3; color: model.status === "locked" ? "#1a1206" : (model.status === "crafting" ? "#0a1f16" : "#0a151a"); border.color: model.status === "locked" ? "#3a2a10" : (model.status === "crafting" ? colors.teal : colors.borderSoft); RowLayout { anchors.fill: parent; anchors.margins: 8; spacing: 8; LabelText { text: "SLOT " + model.index; color: model.status === "locked" ? colors.muted : (model.status === "crafting" ? colors.teal : colors.gold); font.pixelSize: 9; font.weight: Font.Black } LabelText { text: model.status === "locked" ? ("LOCKED " + model.price + " C") : (model.status === "crafting" ? model.name : "READY"); font.pixelSize: 9; font.weight: Font.Black; Layout.fillWidth: true; elide: Text.ElideRight } LabelText { visible: model.status === "crafting"; text: Math.floor(model.time / 3600) + "h " + Math.floor((model.time % 3600) / 60) + "m"; color: colors.gold; font.pixelSize: 9; font.weight: Font.Black } } } } } }
                            }
                        }
                        Panel {
                            Layout.preferredWidth: 320
                            Layout.minimumWidth: 250
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            ColumnLayout {
                                anchors.fill: parent
                                anchors.margins: 14
                                spacing: 8
                                RowLayout { Layout.fillWidth: true; spacing: 8; LabelText { text: "Assign accounts"; font.pixelSize: 18; font.weight: Font.Black; Layout.fillWidth: true; elide: Text.ElideRight } StatusPill { value: root.assignedCount(root.activePlanName()) + " / 50"; accent: colors.teal } }
                                SmallCaption { text: "Click accounts to add or remove them from " + root.activePlanName() }
                                ListView {
                                    Layout.fillWidth: true
                                    Layout.fillHeight: true
                                    clip: true
                                    spacing: 4
                                    model: loginBridge.accounts
                                    ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }
                                    delegate: Rectangle {
                                        width: ListView.view.width
                                        height: 46
                                        radius: 3
                                        property bool assigned: root.assignedToActivePlan(index)
                                        color: assigned ? "#173139" : colors.surface2
                                        border.color: assigned ? colors.teal : colors.borderSoft
                                        MouseArea { anchors.fill: parent; onClicked: root.togglePlanAccount(index) }
                                        RowLayout { anchors.fill: parent; anchors.leftMargin: 10; anchors.rightMargin: 10; spacing: 8; Rectangle { width: 22; height: 22; radius: 3; color: parent.parent.assigned ? colors.teal : "transparent"; border.color: parent.parent.assigned ? colors.teal : colors.border; LabelText { anchors.centerIn: parent; text: parent.parent.parent.assigned ? "V" : ""; color: "#071015"; font.pixelSize: 14; font.weight: Font.Black } } ColumnLayout { Layout.fillWidth: true; Layout.alignment: Qt.AlignVCenter; spacing: 1; LabelText { text: modelData.name; font.pixelSize: 14; font.weight: Font.Black; elide: Text.ElideRight; Layout.fillWidth: true } SmallCaption { text: root.accountPlan(model.index !== undefined ? model.index : index); color: parent.parent.assigned ? colors.teal : colors.muted; font.pixelSize: 10; elide: Text.ElideRight; Layout.fillWidth: true } } LabMultiplierSelector { accountIndex: model.index !== undefined ? model.index : index; Layout.alignment: Qt.AlignVCenter; Layout.preferredWidth: 64; Layout.minimumWidth: 64; Layout.preferredHeight: 24 } Item { Layout.alignment: Qt.AlignVCenter; Layout.preferredWidth: 44; Layout.preferredHeight: 20; Rectangle { anchors.fill: parent; visible: root.accountLoopActive(model.index !== undefined ? model.index : index); radius: 10; color: "#173139"; border.color: colors.teal; border.width: 1; LabelText { anchors.centerIn: parent; text: "LOOP"; color: colors.teal; font.pixelSize: 8; font.weight: Font.Black } } } }
                                    }
                                }
                                SmallCaption { text: "CHEST ROUTING READY // USE THE ASSIGNED PLAN"; color: colors.faint; Layout.fillWidth: true }
                                ActionButton { text: "OPEN CHEST // ALL " + loginBridge.accounts.length + " ACC"; Layout.fillWidth: true; enabled: !loginBridge.busy; onClicked: root.openChest() }
                                SmallCaption { text: loginBridge.accounts.length + " accounts loaded // plan routing active"; color: colors.gold }
                            }
                        }
                        }

                        // AUTOBUY LOG - bottom bar
                    Rectangle {
                        Layout.fillWidth: true
                            Layout.preferredHeight: 56
                            Layout.minimumHeight: 56
                            Layout.maximumHeight: 56
                        color: colors.surface
                        border.color: colors.borderSoft
                        border.width: 1
                        radius: 4
                        RowLayout {
                            anchors.fill: parent
                            anchors.leftMargin: 12
                            anchors.rightMargin: 12
                            spacing: 8
                            LabelText { text: "LOG:"; color: colors.gold; font.pixelSize: 11; font.weight: Font.Black }
                            LabelText { Layout.fillWidth: true; text: loginBridge.logText ? loginBridge.logText.split("\n")[0] : "No activity yet"; color: colors.text; font.pixelSize: 11; elide: Text.ElideRight; font.family: "Consolas" }
                        }
                        }
                    }
                    // Inventory
                    RowLayout {
                        Layout.margins: 26
                        spacing: 14

                        Panel {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            clip: true
                            ColumnLayout {
                                anchors.fill: parent
                                anchors.margins: 18
                                spacing: 12
                                RowLayout {
                                    Layout.fillWidth: true
                                    LabelText { text: "Accounts"; font.pixelSize: 21; font.weight: Font.Black; Layout.fillWidth: true }
                                    StatusPill { value: loginBridge.accounts.length + " QW"; accent: colors.teal }
                                    // La selección del archivo puede hacerse mientras
                                    // corre el scan inicial; la petición queda en cola.
                                    ActionButton { text: "AÑADIR QW"; enabled: true; onClicked: root.addQw() }
                                }
                                SmallCaption { text: "QW accounts scanned from disk with coins and lab slots" }
                                ListView {
                                    id: accountsList
                                    Layout.fillWidth: true
                                    Layout.fillHeight: true
                                    clip: true
                                    spacing: 6
                                    model: loginBridge.accounts
                                    ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }
                                    delegate: Rectangle {
                                        width: ListView.view.width
                                        height: 46
                                        radius: 3
                                        property bool isSelected: root.selectedAccount === index
                                        color: isSelected ? "#173139" : colors.surface2
                                        border.color: isSelected ? colors.teal : colors.borderSoft
                                        MouseArea { anchors.fill: parent; onClicked: root.selectedAccount = index }
                                        RowLayout {
                                            anchors.fill: parent
                                            anchors.margins: 9
                                            spacing: 8
                                            Rectangle { width: 18; height: 18; radius: 3; color: parent.parent.isSelected ? colors.teal : "transparent"; border.color: parent.parent.isSelected ? colors.teal : colors.border; LabelText { anchors.centerIn: parent; text: parent.parent.parent.isSelected ? "V" : ""; color: "#071015"; font.pixelSize: 11; font.weight: Font.Black } }
                                            ColumnLayout {
                                                Layout.fillWidth: true
                                                spacing: 2
                                                LabelText { text: modelData.name; font.pixelSize: 12; font.weight: Font.Black; elide: Text.ElideRight }
                                                SmallCaption { text: modelData.ok ? (modelData.labSlots + " lab slots // " + modelData.lockedSlots + " locked") : ("OFFLINE: " + modelData.error) }
                                            }
                                            LabelText { text: modelData.ok ? modelData.coins + " C" : "--"; color: colors.gold; font.pixelSize: 12; font.weight: Font.Black; Layout.alignment: Qt.AlignRight | Qt.AlignVCenter; Layout.preferredWidth: 90; horizontalAlignment: Text.AlignRight }
                                            GhostButton { text: "X"; Layout.preferredWidth: 24; Layout.preferredHeight: 20; onClicked: loginBridge.removeAccountAt(index) }
                                        }
                                    }
                                }
                            }
                        }

                        Panel {
                            Layout.preferredWidth: 330
                            Layout.fillHeight: true
                            ColumnLayout {
                                anchors.fill: parent
                                anchors.margins: 14
                                spacing: 8
                                RowLayout {
                                    Layout.fillWidth: true
                                    LabelText { text: "Account Labs"; font.pixelSize: 17; font.weight: Font.Black; Layout.fillWidth: true }
                                    StatusPill { value: loginBridge.allLabs.length + " ACC"; accent: colors.purple }
                                }
                                SmallCaption { text: "Crafting status of every QW account" }
                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: 8
                                    ActionButton { text: "SCAN LABS"; enabled: !loginBridge.busy; onClicked: loginBridge.scanAllLabs() }
                                }
                                ListView {
                                    Layout.fillWidth: true
                                    Layout.fillHeight: true
                                    clip: true
                                    spacing: 6
                                    model: root.liveLabs
                                    ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }
                                    delegate: Item {
                                        width: ListView.view.width
                                        height: 32 + Math.max(0, (modelData.ok ? modelData.slots.length : 0)) * 28
                                        property var accountData: modelData
                                        property int accountIndex: index
                                        Rectangle {
                                            width: parent.width
                                                height: 26
                                            radius: 3
                                            color: colors.surface2
                                            border.color: colors.borderSoft
                                            RowLayout {
                                                anchors.fill: parent
                                                anchors.margins: 8
                                                spacing: 6
                                                LabelText { text: parent.parent.parent.accountData.name; font.pixelSize: 12; font.weight: Font.Black; Layout.fillWidth: true; elide: Text.ElideRight }
                                                StatusPill { value: "x" + root.labMultiplier(index); accent: root.labMultiplier(index) > 1 ? colors.gold : colors.purple }
                                                LabelText { text: parent.parent.parent.accountData.ok ? "ONLINE" : "OFFLINE"; color: parent.parent.parent.accountData.ok ? colors.teal : "#e56b6b"; font.pixelSize: 10; font.weight: Font.Black }
    }
}

                                         Repeater {
                                             model: parent.accountData.ok ? parent.accountData.slots : []
                                    delegate: Item {
                                        id: labSlotDelegate
                                        width: parent.width
                                        y: 28 + index * 28
                                        height: 26
                                        property int ownerAccountIndex: parent && parent.accountIndex !== undefined ? parent.accountIndex : -1
                                                 property string slotBg: modelData.status === "locked" ? "#1a1206" : ((root.slotIsDone(modelData) || (modelData.status !== "crafting" && modelData.name !== "")) ? "#0d2a26" : (modelData.status === "crafting" ? "#0a1f16" : "#0a151a"))
                                                 Rectangle {
                                                     anchors.fill: parent
                                                     radius: 2
                                                     color: parent.slotBg
                                                     RowLayout {
                                                         anchors.fill: parent
                                                         anchors.margins: 6
                                                         spacing: 6
                                                          LabelText { text: "S" + modelData.index; color: modelData.status === "locked" ? colors.muted : ((root.slotIsDone(modelData) || (modelData.status !== "crafting" && modelData.name !== "")) ? colors.teal : (modelData.status === "crafting" ? colors.teal : colors.gold)); font.pixelSize: 11; font.weight: Font.Black; Layout.preferredWidth: 20 }
                                                          Image { visible: modelData.status !== "locked" && modelData.name !== "" && root.labImgForServerName(modelData.name) !== ""; Layout.preferredWidth: 24; Layout.preferredHeight: 24; source: root.labImgForServerName(modelData.name); fillMode: Image.PreserveAspectFit; smooth: true; mipmap: true }
                                                          LabelText { text: modelData.status === "locked" ? "LOCKED " + modelData.price + "C" : ((root.slotIsDone(modelData) || (modelData.status !== "crafting" && modelData.name !== "")) ? "READY" : (modelData.status === "crafting" ? root.labSlotDisplayName(modelData, labSlotDelegate.ownerAccountIndex) : "READY")); color: (root.slotIsDone(modelData) || (modelData.status !== "crafting" && modelData.name !== "")) ? colors.teal : colors.text; font.pixelSize: 11; font.weight: Font.Black; Layout.fillWidth: true; elide: Text.ElideRight }
                                                          LabelText { visible: modelData.status === "crafting" && !root.slotIsDone(modelData); text: root.formatRemaining(modelData) + " [" + root.labTickCount + "]"; color: colors.gold; font.pixelSize: 11; font.weight: Font.Black }
                                                     }
                                                 }
                                             }
                                         }
                                    }
                                }
                            }
                        }


                }

                    // CRAFT HISTORY VIEW
                    RowLayout {
                        Layout.margins: 26
                        spacing: 14
                        Panel {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            ColumnLayout {
                                anchors.fill: parent
                                anchors.margins: 16
                                spacing: 10
                                RowLayout {
                                    Layout.fillWidth: true
                                    LabelText { text: "Craft History"; font.pixelSize: 20; font.weight: Font.Black; Layout.fillWidth: true }
                                    StatusPill { value: loginBridge.accounts.length + " ACC"; accent: colors.purple }
                                }
                                SmallCaption { text: "Successful potion crafts tracked locally for every QW account" }
                                ListView {
                                    Layout.fillWidth: true
                                    Layout.fillHeight: true
                                    clip: true
                                    spacing: 8
                                    model: loginBridge.accounts
                                    ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }
                                    delegate: Panel {
                                        width: ListView.view.width
                                        height: 92
                                        color: colors.surface2
                                        RowLayout {
                                            anchors.fill: parent
                                            anchors.leftMargin: 14
                                            anchors.rightMargin: 14
                                            spacing: 12
                                            Rectangle {
                                                Layout.preferredWidth: 46
                                                Layout.preferredHeight: 46
                                                radius: 8
                                                color: "#102c3b"
                                                border.color: colors.teal
                                                border.width: 1
                                                LabelText { anchors.centerIn: parent; text: "QW"; color: colors.teal; font.pixelSize: 12; font.weight: Font.Black; font.letterSpacing: 1.0 }
                                            }
                                            ColumnLayout {
                                                Layout.fillWidth: true
                                                spacing: 3
                                                LabelText { text: modelData.name; font.pixelSize: 15; font.weight: Font.Black; Layout.fillWidth: true; elide: Text.ElideRight }
                                                SmallCaption { text: modelData.lastCraftAt ? "LAST CRAFT // " + modelData.lastCraftAt.replace("T", " ").slice(0, 19) : "NO CRAFTS RECORDED YET"; color: modelData.lastCraftAt ? colors.teal : colors.muted }
                                                // fila de sprites del historial (sprite + cantidad por poción)
                                                RowLayout {
                                                    Layout.fillWidth: true
                                                    spacing: 10
                                                    Repeater {
                                                        model: modelData.craftHistory || []
                                                        delegate: RowLayout {
                                                            spacing: 4
                                                            Image {
                                                                Layout.preferredWidth: 26
                                                                Layout.preferredHeight: 26
                                                                source: root.historyImgForName(modelData.name)
                                                                fillMode: Image.PreserveAspectFit
                                                                smooth: true
                                                                mipmap: true
                                                            }
                                                            LabelText { text: String(root.historyCount(modelData)) + "x"; color: colors.gold; font.pixelSize: 12; font.weight: Font.Black }
                                                        }
                                                    }
                                                    Item { Layout.fillWidth: true }
                                                }
                                                SmallCaption { text: root.craftHistorySummary(modelData.craftHistory); color: colors.muted; elide: Text.ElideRight; visible: (modelData.craftHistory || []).length > 0 }
                                            }
                                            }
                                            Rectangle {
                                                Layout.preferredWidth: 126
                                                Layout.preferredHeight: 58
                                                radius: 7
                                                color: "#0a1826"
                                                border.color: colors.border
                                                ColumnLayout {
                                                    anchors.fill: parent
                                                    anchors.margins: 8
                                                    spacing: 1
                                                    LabelText { text: String(root.totalCrafted(modelData)); color: colors.gold; font.pixelSize: 22; font.weight: Font.Black; Layout.fillWidth: true; horizontalAlignment: Text.AlignHCenter }
                                                    SmallCaption { text: "POTIONS CRAFTED"; color: colors.gold; font.pixelSize: 8; Layout.fillWidth: true; horizontalAlignment: Text.AlignHCenter }
                                                }
                                            }
                                        }
                                    }
                                }
                                Panel {
                                    Layout.fillWidth: true
                                    Layout.preferredHeight: 42
                                    color: colors.surface2
                                    RowLayout {
                                        anchors.fill: parent
                                        anchors.leftMargin: 12
                                        anchors.rightMargin: 12
                                        spacing: 8
                                        Rectangle { width: 6; height: 6; radius: 3; color: colors.teal }
                                    SmallCaption { text: "History updates after a successful CRAFT or AUTOBUY operation."; color: colors.teal; Layout.fillWidth: true }
                                    }
                                }
                            }
                        }

                    // SHOP VIEW
                    RowLayout {
                        Layout.margins: 26
                        spacing: 14
                        Panel {
                            Layout.preferredWidth: 380
                            Layout.fillHeight: true
                            clip: true
                            ColumnLayout {
                                anchors.fill: parent
                                anchors.margins: 12
                                spacing: 6
                                RowLayout { Layout.fillWidth: true; LabelText { text: "SHOP"; font.pixelSize: 16; font.weight: Font.Black; Layout.fillWidth: true } StatusPill { value: "BUY"; accent: colors.gold } }
                                SmallCaption { text: "Buy potions on selected accounts (deducts coins)" }
                                ListView { Layout.fillWidth: true; Layout.fillHeight: true; clip: true; spacing: 2; model: root.shopItems; delegate: Rectangle { width: ListView.view.width; height: 40; radius: 3; color: colors.surface2; border.color: colors.borderSoft; RowLayout { anchors.fill: parent; anchors.leftMargin: 6; anchors.rightMargin: 4; anchors.topMargin: 4; anchors.bottomMargin: 4; spacing: 8; Rectangle { width: 30; height: 30; radius: 4; color: "#0a151a"; border.color: colors.borderSoft; Image { anchors.centerIn: parent; width: 26; height: 26; source: "qrc:/Utopia/assets/potions/sprites/" + modelData.img; fillMode: Image.PreserveAspectFit; smooth: true; mipmap: true } } ColumnLayout { Layout.fillWidth: true; Layout.alignment: Qt.AlignVCenter; spacing: 2; LabelText { text: modelData.name; font.pixelSize: 11; font.weight: Font.Black; elide: Text.ElideRight; Layout.fillWidth: true } LabelText { text: modelData.price + " C"; color: colors.gold; font.pixelSize: 10; font.weight: Font.Black; Layout.fillWidth: true; horizontalAlignment: Text.AlignRight } } ActionButton { text: "BUY"; Layout.preferredWidth: 52; Layout.preferredHeight: 24; Layout.alignment: Qt.AlignVCenter; onClicked: { root.buyPacksItemId = modelData.id; root.buyPacksItemName = modelData.name; root.buyPacks = 1; root.buyPacksItemPack = modelData.pack; buyPacksDialog.open() } } } } }
                            }
                        }
                        Panel {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            clip: true
                            ColumnLayout {
                                anchors.fill: parent
                                anchors.margins: 12
                                spacing: 6
                                LabelText { text: "ACCOUNTS (CLICK TO SELECT)"; font.pixelSize: 16; font.weight: Font.Black }
                                SmallCaption { text: "Selected accounts receive the purchase" }
                                ListView { Layout.fillWidth: true; Layout.fillHeight: true; clip: true; spacing: 4; model: loginBridge.accounts; delegate: Rectangle { width: ListView.view.width; height: 42; radius: 3; color: root.buySelection[index] ? "#173139" : colors.surface2; border.color: root.buySelection[index] ? colors.teal : colors.borderSoft; MouseArea { anchors.fill: parent; onClicked: root.toggleBuyAccount(index) } RowLayout { anchors.fill: parent; anchors.leftMargin: 8; anchors.rightMargin: 8; spacing: 8; Rectangle { width: 20; height: 20; radius: 3; color: root.buySelection[index] ? colors.teal : "transparent"; border.color: root.buySelection[index] ? colors.teal : colors.border; LabelText { anchors.centerIn: parent; text: root.buySelection[index] ? "V" : ""; color: "#071015"; font.pixelSize: 13; font.weight: Font.Black } } LabelText { text: modelData.name; font.pixelSize: 14; font.weight: Font.Black; Layout.fillWidth: true; elide: Text.ElideRight } LabelText { text: modelData.coins + " C"; color: colors.gold; font.pixelSize: 13; font.weight: Font.Black; Layout.preferredWidth: 78; horizontalAlignment: Text.AlignRight } } } }
                            }
                        }
                    }
            // Barra de estado global
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 34
                Layout.leftMargin: 26
                Layout.rightMargin: 26
                color: 'transparent'
                RowLayout {
                    anchors.fill: parent
                    spacing: 10
                    Rectangle { width: 7; height: 7; radius: 4; color: loginBridge.busy ? colors.gold : (loginBridge.loggedIn ? colors.teal : colors.muted) }
                    LabelText { text: loginBridge.status; color: colors.text; font.pixelSize: 11; font.weight: Font.Black; elide: Text.ElideRight; Layout.fillWidth: true }
                }
            }
        }
    }

    component ProgressBar: Item {
        id: progress
        property real value: 0.5
        implicitHeight: 8
        Rectangle { anchors.fill: parent; radius: 4; color: "#071015"; border.color: colors.border }
        Rectangle { width: Math.max(5, parent.width * progress.value); height: parent.height; radius: 4; color: colors.teal }
    }

    Rectangle { visible: root.showToast; anchors.horizontalCenter: parent.horizontalCenter; anchors.bottom: parent.bottom; anchors.bottomMargin: 24; width: toastLabel.implicitWidth + 34; height: 40; radius: 20; color: colors.surface3; border.color: colors.teal; z: 20; LabelText { id: toastLabel; anchors.centerIn: parent; text: root.toastText; font.weight: Font.Black } }

    Dialog {
        id: planRenameDialog
        title: "Rename plan"
        modal: true
        anchors.centerIn: parent
        standardButtons: Dialog.Ok | Dialog.Cancel
        onAccepted: root.renamePlan(root.planRenameIndex, planRenameField.text)
        background: Rectangle { color: colors.surface3; radius: 8; border.color: colors.border; border.width: 1 }
        header: Rectangle {
            implicitHeight: 44
            color: colors.surface
            radius: 8
            border.color: colors.border
            border.width: 1
            LabelText {
                anchors.left: parent.left
                anchors.leftMargin: 18
                anchors.verticalCenter: parent.verticalCenter
                text: "RENAME PLAN"
                color: colors.text
                font.pixelSize: 14
                font.weight: Font.Black
            }
        }
        contentItem: ColumnLayout {
            spacing: 8
            TextField {
                id: planRenameField
                Layout.fillWidth: true
                placeholderText: "New plan name"
                text: root.planRenameIndex >= 0 ? plansModel.get(root.planRenameIndex).name : ""
                font.family: "Bahnschrift"
                font.pixelSize: 13
                color: colors.text
                placeholderTextColor: colors.muted
                background: Rectangle {
                    color: colors.surface2
                    radius: 4
                    border.color: colors.border
                    border.width: 1
                }
            }
        }
    }
Dialog {
    id: buyPacksDialog
    title: "Buy " + root.buyPacksItemName
    modal: true
    standardButtons: Dialog.Ok | Dialog.Cancel
    onAccepted: root.buyItemOnSelected(root.buyPacksItemId, root.buyPacks)
    background: Rectangle { color: colors.surface3; radius: 8; border.color: colors.border; border.width: 1 }
    header: Rectangle {
        implicitHeight: 44
        color: colors.surface
        radius: 8
        border.color: colors.border
        border.width: 1
        LabelText {
            anchors.left: parent.left
            anchors.leftMargin: 18
            anchors.verticalCenter: parent.verticalCenter
            text: "BUY " + root.buyPacksItemName
            color: colors.text
            font.pixelSize: 14
            font.weight: Font.Black
        }
    }
    contentItem: ColumnLayout {
        spacing: 10
        LabelText { text: "Each pack = " + root.buyPacksItemPack + "x " + root.buyPacksItemName; color: colors.text; font.pixelSize: 11; font.weight: Font.Black }
        RowLayout {
            Layout.fillWidth: true
            spacing: 8
            ActionButton { text: "-"; Layout.preferredWidth: 32; Layout.preferredHeight: 26; onClicked: root.buyPacks = Math.max(1, root.buyPacks - 1) }
            TextField {
                id: buyPacksField
                Layout.fillWidth: true
                text: root.buyPacks
                font.family: "Bahnschrift"
                font.pixelSize: 13
                horizontalAlignment: Text.AlignHCenter
                color: colors.text
                validator: IntValidator { bottom: 1; top: 99 }
                onTextChanged: root.buyPacks = parseInt(text) > 0 ? parseInt(text) : 1
            }
            ActionButton { text: "+"; Layout.preferredWidth: 32; Layout.preferredHeight: 26; onClicked: root.buyPacks = Math.min(99, root.buyPacks + 1) }
        }
        LabelText { text: "Total: " + (root.buyPacks * root.buyPacksItemPack) + "x " + root.buyPacksItemName; color: colors.teal; font.pixelSize: 11; font.weight: Font.Black }
    }
}

Dialog {
    id: chestResultsDialog
    title: "Chest rewards"
    modal: true
    width: 560
    height: 480
    x: (parent.width - width) / 2
    y: (parent.height - height) / 2
    background: Rectangle { color: colors.surface3; radius: 8; border.color: colors.border; border.width: 1 }
    header: Rectangle {
        implicitHeight: 44
        color: colors.surface
        radius: 8
        border.color: colors.border
        border.width: 1
        LabelText {
            anchors.left: parent.left
            anchors.leftMargin: 18
            anchors.verticalCenter: parent.verticalCenter
            text: "CHEST REWARDS"
            color: colors.gold
            font.pixelSize: 14
            font.weight: Font.Black
        }
    }
    contentItem: ColumnLayout {
        spacing: 8
        LabelText {
            visible: loginBridge.busy && loginBridge.chestResults.length === 0
            text: "SCANNING CHESTS..."
            color: colors.teal
            font.pixelSize: 11
            font.weight: Font.Black
            Layout.fillWidth: true
            horizontalAlignment: Text.AlignHCenter
        }
        ListView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            spacing: 6
            model: loginBridge.chestResults
            delegate: Rectangle {
                width: ListView.view.width
                height: Math.max(64, chestRowContent.implicitHeight + 16)
                radius: 4
                color: modelData.ok ? "#0a1f16" : "#1a1206"
                border.color: modelData.ok ? colors.teal : "#3a2a10"
                border.width: 1
                ColumnLayout {
                    id: chestRowContent
                    anchors.fill: parent
                    anchors.margins: 8
                    spacing: 4
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: 8
                        LabelText { text: modelData.name; font.pixelSize: 12; font.weight: Font.Black; color: colors.text; elide: Text.ElideRight; Layout.fillWidth: true }
                        StatusPill { value: modelData.ok ? "OPENED" : "FAILED"; accent: modelData.ok ? colors.teal : "#c0392b" }
                    }
                    LabelText {
                        visible: !modelData.ok
                        text: root.chestErrorText(modelData.error || "")
                        font.pixelSize: 10
                        color: "#e67e22"
                        elide: Text.ElideRight
                        Layout.fillWidth: true
                    }
                    Flow {
                        visible: modelData.ok
                        Layout.fillWidth: true
                        spacing: 6
                        Repeater {
                            model: modelData.rewards || []
                            delegate: Rectangle {
                                width: 158
                                height: 42
                                radius: 4
                                color: "#081722"
                                border.color: colors.borderSoft
                                border.width: 1
                                RowLayout {
                                    anchors.fill: parent
                                    anchors.margins: 4
                                    spacing: 5
                                    Image {
                                        width: 26
                                        height: 26
                                        Layout.preferredWidth: 26
                                        Layout.preferredHeight: 26
                                        source: root.chestRewardImg(modelData)
                                        fillMode: Image.PreserveAspectFit
                                        smooth: true
                                        mipmap: true
                                    }
                                    ColumnLayout {
                                        spacing: 0
                                        Layout.fillWidth: true
                                        LabelText {
                                            text: root.chestRewardName(modelData)
                                            font.pixelSize: 9
                                            font.weight: Font.Black
                                            elide: Text.ElideRight
                                            Layout.fillWidth: true
                                        }
                                        LabelText {
                                            text: "x" + (modelData.amount || 1)
                                            color: colors.gold
                                            font.pixelSize: 9
                                            font.weight: Font.Black
                                        }
                                    }
                                }
                            }
                        }
                    }
                    LabelText {
                        visible: modelData.ok && modelData.coins >= 0
                        text: "BALANCE: " + modelData.coins + " C"
                        font.pixelSize: 9
                        color: colors.gold
                        font.weight: Font.Black
                    }
                }
            }
        }
        ActionButton { text: "CLOSE"; Layout.fillWidth: true; Layout.preferredHeight: 32; onClicked: chestResultsDialog.close() }
    }
}
}
}
}

