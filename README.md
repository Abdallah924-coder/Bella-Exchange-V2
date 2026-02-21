# Bella Exchange v2

Plateforme d'echange crypto (achat/vente) avec:
- 6 pages principales: `Accueil`, `Achat`, `Vente`, `Contact`, `Admin`, `Profil`
- Authentification (inscription/connexion/deconnexion)
- Reinitialisation mot de passe par email (mot de passe oublie)
- Historique transactions recentes sur profil
- Validation admin + envoi d'email automatique
- Landing page pro + tableau 10 cryptos (API prix live CoinGecko)
- Taux fixes: achat `635 FCFA`, vente `590 FCFA`
- Theme clair/sombre
- Version App preparee (PWA: manifest + service worker)
- Animation de chargement \"tourbillon univers\" (2 secondes)

## Lancement

```bash
cd /home/dona/bella-exchange-v2
cp .env.example .env
npm install
npm run dev
```

Ouvrir: `http://localhost:3000`

Compte admin par defaut:
- Email: `admin@bellaexchange.cg`
- Mot de passe: `Admin123!`

Pense a changer ces identifiants dans `.env`.

## SMTP reel (production)

Renseigne les variables SMTP dans `.env`:
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASS`
- `SMTP_SECURE` (`true` pour 465, sinon `false`)
- `SMTP_REQUIRE_TLS`
- `SMTP_FROM`
- `ADMIN_NOTIFY_EMAIL` (email qui recoit les nouvelles commandes)

Si `SMTP_HOST` est vide, l'app passe en mode mock email (console).

## Variables utiles auth/admin

- `ADMIN_EMAIL`
- `ADMIN_PASSWORD`
- `ADMIN_PHONE`
- `BASE_URL` (utilise pour les liens de reset password envoyes par mail)

## Notifications Telegram (admin)

Variables `.env`:
- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`

Etapes:
1. Ouvre Telegram et cherche `@BotFather`.
2. Lance `/newbot`, donne un nom puis un username (finissant par `bot`).
3. Copie le token fourni par BotFather vers `TELEGRAM_BOT_TOKEN`.
4. Ouvre une conversation avec ton bot et envoie un message (ex: `start`).
5. Va sur `https://api.telegram.org/bot<TON_TOKEN>/getUpdates`.
6. Recupere `chat.id` dans la reponse JSON et mets-le dans `TELEGRAM_CHAT_ID`.

## Configuration adresses reseaux

Depuis la page `Admin`, tu peux renseigner les adresses de depot par crypto/reseau.

## Hebergement Render

1. Push le dossier sur GitHub.
2. Sur Render: `New +` -> `Blueprint`.
3. Selectionne le repo, Render detecte `render.yaml`.
4. Ajoute toutes les variables de `.env` dans `Environment`.
5. Deploie.

## Base de donnees (PostgreSQL recommande en production)

Pour la production, configure `DATABASE_URL` (Render Postgres).  
Quand `DATABASE_URL` est defini, l'application stocke les donnees en PostgreSQL.

- `DATABASE_URL` : URL complete de connexion Postgres
- `DATABASE_SSL` : `false` (Render interne) ou `true` selon ton provider

Si `DATABASE_URL` est vide, l'application utilise les fichiers JSON locaux.

## Stockage local (JSON, mode fallback)

- Utilisateurs: `data/users.json`
- Transactions: `data/transactions.json`
- Resets password: `data/password_resets.json`
