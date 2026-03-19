const mongoose = require('mongoose');

const CARD_COLOR_VALUES = ['W', 'U', 'B', 'R', 'G'];
const DECK_FORMAT_VALUES = [
  'standard',
  'pioneer',
  'modern',
  'legacy',
  'vintage',
  'pauper',
  'commander',
];

const cardPriceSchema = new mongoose.Schema(
  {
    usd: { type: Number, default: null, min: 0 },
    usdFoil: { type: Number, default: null, min: 0 },
    eur: { type: Number, default: null, min: 0 },
    eurFoil: { type: Number, default: null, min: 0 },
    tix: { type: Number, default: null, min: 0 },
  },
  { _id: false }
);

const cardSnapshotSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, trim: true, maxlength: 120 },
    oracleId: { type: String, default: null, trim: true, maxlength: 120 },
    name: { type: String, required: true, trim: true, maxlength: 200 },
    manaCost: { type: String, default: '', maxlength: 80 },
    manaValue: { type: Number, required: true, min: 0, max: 100 },
    releasedAt: { type: String, default: '', maxlength: 20 },
    typeLine: { type: String, required: true, maxlength: 240 },
    oracleText: { type: String, default: '', maxlength: 6000 },
    colors: {
      type: [{ type: String, enum: CARD_COLOR_VALUES }],
      default: [],
    },
    colorIdentity: {
      type: [{ type: String, enum: CARD_COLOR_VALUES }],
      default: [],
    },
    setCode: { type: String, required: true, trim: true, lowercase: true, maxlength: 20 },
    setName: { type: String, required: true, trim: true, maxlength: 120 },
    collectorNumber: { type: String, required: true, trim: true, maxlength: 40 },
    rarity: { type: String, required: true, trim: true, maxlength: 40 },
    legalities: {
      type: Object,
      default: {},
    },
    imageUrl: { type: String, default: '', trim: true, maxlength: 1000 },
    largeImageUrl: { type: String, default: '', trim: true, maxlength: 1000 },
    prices: {
      type: cardPriceSchema,
      default: () => ({
        usd: null,
        usdFoil: null,
        eur: null,
        eurFoil: null,
        tix: null,
      }),
    },
  },
  { _id: false, strict: true }
);

const deckEntrySchema = new mongoose.Schema(
  {
    quantity: { type: Number, required: true, min: 1, max: 250 },
    card: { type: cardSnapshotSchema, required: true },
  },
  { _id: false, strict: true }
);

const grimoireDeckSchema = new mongoose.Schema(
  {
    ownerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    deckId: {
      type: String,
      required: true,
      trim: true,
      maxlength: 120,
    },
    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: 120,
    },
    format: {
      type: String,
      required: true,
      enum: DECK_FORMAT_VALUES,
      default: 'standard',
    },
    mainboard: {
      type: [deckEntrySchema],
      default: [],
      validate: {
        validator: (entries) => Array.isArray(entries) && entries.length <= 250,
        message: 'Mainboard can contain at most 250 unique card entries.',
      },
    },
    sideboard: {
      type: [deckEntrySchema],
      default: [],
      validate: {
        validator: (entries) => Array.isArray(entries) && entries.length <= 120,
        message: 'Sideboard can contain at most 120 unique card entries.',
      },
    },
    notes: {
      type: String,
      default: '',
      maxlength: 8000,
    },
    matchupNotes: {
      type: String,
      default: '',
      maxlength: 8000,
    },
    budgetTargetUsd: {
      type: Number,
      default: null,
      min: 0,
      max: 100000,
    },
    deckCreatedAt: {
      type: Date,
      required: true,
    },
    deckUpdatedAt: {
      type: Date,
      required: true,
      index: true,
    },
  },
  {
    timestamps: true,
    strict: true,
  }
);

grimoireDeckSchema.index({ ownerId: 1, deckId: 1 }, { unique: true });

module.exports = mongoose.model('GrimoireDeck', grimoireDeckSchema);
