const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const app = express();

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// --- DATABASE CONNECTION ---
const uri = "mongodb+srv://adminupgames2026:78simon87@cluster0.turx6r1.mongodb.net/UpGames?retryWrites=true&w=majority";
mongoose.connect(uri)
  .then(() => console.log("🚀 CORE SYSTEM ONLINE: Universal English Variables Synced"))
  .catch(err => console.error("❌ CONNECTION ERROR:", err));

// --- DATA MODELS ---

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, index: true },
    password: { type: String, required: true },
    avatar: { type: String, default: "" },
    isVerified: { type: Boolean, default: false },
    rank: { type: String, default: "user" }, 
    followers: { type: Number, default: 0 },
    appStyle: {
        themeColor: { type: String, default: '#5EFF43' },
        layoutMode: { type: String, default: 'grid' }
    }
}, { timestamps: true });

const User = mongoose.model("User", UserSchema);

const ItemSchema = new mongoose.Schema({
    username: { type: String, index: true }, // The uploader
    title: { type: String, required: true },
    description: String,
    image: String,
    link: String,
    status: { type: String, default: "pending", index: true }, 
    category: { type: String, default: "General" },
    reports: { type: Number, default: 0 }
}, { timestamps: true });

const Item = mongoose.model('Item', ItemSchema);

const FavoriteSchema = new mongoose.Schema({
    username: String,
    itemId: { type: mongoose.Schema.Types.ObjectId, ref: 'Item' }
});

const Favorite = mongoose.model('Favorite', FavoriteSchema);

const CommentSchema = new mongoose.Schema({
    username: String, 
    text: String, 
    itemId: String, 
    date: { type: Date, default: Date.now }
});

const Comment = mongoose.model('Comment', CommentSchema);

// --- API ROUTES ---

// [1. AUTHENTICATION & PROFILE]
app.post("/auth/login", async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username, password });
    if (user) res.json({ success: true, ...user._doc });
    else res.status(401).json({ success: false, message: "Invalid credentials" });
});

app.post("/auth/register", async (req, res) => {
    const { username, password } = req.body;
    const exists = await User.findOne({ username });
    if (exists) return res.status(400).json({ success: false, message: "User already exists" });
    const newUser = new User({ username, password });
    await newUser.save();
    res.json({ success: true, username: newUser.username });
});

app.get("/auth/user/:username", async (req, res) => {
    const user = await User.findOne({ username: req.params.username }).select('-password');
    res.json(user);
});

app.get("/auth/users", async (req, res) => {
    const users = await User.find().select('-password');
    res.json(users);
});

app.put("/auth/update-avatar", async (req, res) => {
    await User.findOneAndUpdate({ username: req.body.username }, { avatar: req.body.newPhoto });
    res.json({ success: true });
});

app.put("/auth/follow/:target", async (req, res) => {
    const value = req.body.action === "increase" ? 1 : -1;
    await User.findOneAndUpdate({ username: req.params.target }, { $inc: { followers: value } });
    res.json({ ok: true });
});

// [2. APP STYLE & AURA]
app.post('/api/user/update-style', async (req, res) => {
    const { username, themeColor } = req.body;
    await User.findOneAndUpdate({ username }, { $set: { "appStyle.themeColor": themeColor } });
    res.json({ success: true });
});

// [3. ITEMS & CONTENT MANAGEMENT]
app.get("/items", async (req, res) => {
    const items = await Item.find().sort({ createdAt: -1 });
    res.json(items);
});

app.get("/items/user/:username", async (req, res) => {
    const items = await Item.find({ username: req.params.username });
    res.json(items);
});

app.post("/items/add", async (req, res) => {
    const newItem = new Item({ ...req.body, status: "pending" });
    await newItem.save();
    res.json({ ok: true });
});

app.put("/items/approve/:id", async (req, res) => {
    await Item.findByIdAndUpdate(req.params.id, { status: "approved" });
    res.json({ ok: true });
});

app.put("/items/report/:id", async (req, res) => {
    const item = await Item.findByIdAndUpdate(req.params.id, { $inc: { reports: 1 } }, { new: true });
    // Auto-hide if reports reach threshold
    if (item.reports >= 10) await Item.findByIdAndUpdate(req.params.id, { status: "pending" });
    res.json({ ok: true, reports: item.reports });
});

app.delete("/items/:id", async (req, res) => {
    await Item.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
});

// [4. VAULT / FAVORITES]
app.get("/favorites/:username", async (req, res) => {
    const list = await Favorite.find({ username: req.params.username }).populate('itemId');
    const validItems = list.filter(f => f.itemId).map(f => ({ ...f.itemId._doc, favId: f._id }));
    res.json(validItems);
});

app.post("/favorites/add", async (req, res) => {
    const { username, itemId } = req.body;
    const exists = await Favorite.findOne({ username, itemId });
    if (!exists) await new Favorite({ username, itemId }).save();
    res.json({ ok: true });
});

app.delete("/favorites/delete/:id", async (req, res) => {
    await Favorite.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
});

// [5. COMMENTS]
app.get("/comments/:id", async (req, res) => {
    const c = await Comment.find({ itemId: req.params.id }).sort({ date: -1 });
    res.json(c);
});

app.post("/comments", async (req, res) => {
    await new Comment(req.body).save();
    res.json({ ok: true });
});

// [6. ADMIN CONTROL]
app.put("/auth/admin/update-rank", async (req, res) => {
    const { id, isVerified, rank } = req.body;
    await User.findByIdAndUpdate(id, { isVerified, rank });
    res.json({ success: true });
});

app.delete("/auth/users/:id", async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
});

// --- SERVER START ---
const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ UP GAMES SERVER READY ON PORT ${PORT}`);
});
