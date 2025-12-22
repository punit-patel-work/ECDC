# Deploying ECDC to Netlify

## Prerequisites
- [Netlify account](https://app.netlify.com/signup)
- [Netlify CLI](https://docs.netlify.com/cli/get-started/) (optional, for command-line deploy)

---

## Option 1: Deploy via Netlify Dashboard (Easiest)

### Step 1: Push to GitHub
```bash
cd c:\Users\Punit\Desktop\Programming\ECDC
git init
git add .
git commit -m "Initial commit - ECDC encryption app"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/ecdc.git
git push -u origin main
```

### Step 2: Connect to Netlify
1. Go to [app.netlify.com](https://app.netlify.com)
2. Click **"Add new site"** → **"Import an existing project"**
3. Choose **GitHub** and authorize access
4. Select your **ecdc** repository
5. Configure build settings:
   - **Build command:** *(leave empty)*
   - **Publish directory:** `public`
6. Click **"Deploy site"**

### Step 3: Done!
Your app will be live at `https://your-site-name.netlify.app`

---

## Option 2: Deploy via Netlify CLI

### Install CLI
```bash
npm install -g netlify-cli
```

### Login & Deploy
```bash
cd c:\Users\Punit\Desktop\Programming\ECDC
netlify login
netlify deploy --prod
```

When prompted:
- Create a new site
- Publish directory: `public`

---

## Project Structure for Netlify

```
ECDC/
├── netlify.toml              # Netlify configuration
├── netlify/
│   └── functions/
│       └── api.js            # Serverless API handler
├── public/                   # Static files (served directly)
│   ├── index.html
│   ├── styles.css
│   └── app.js
├── server.js                 # Local development server
└── package.json
```

---

## How It Works

| Environment | API Calls |
|-------------|-----------|
| **Local** (`npm start`) | `/api/*` → Express server |
| **Netlify** | `/api/*` → `/.netlify/functions/api/*` |

The `netlify.toml` file automatically redirects API calls to serverless functions.

---

## Notes

- **File encryption** may not work on Netlify due to serverless function limitations (10MB payload limit)
- **ChaCha20 and Blowfish** are excluded from Netlify functions (require native modules not available in serverless)
- **Local development** with `npm start` has full functionality

### For Local Development
```bash
npm start
# Open http://localhost:3000
```

### For Netlify Functions Testing Locally
```bash
npm install -g netlify-cli
netlify dev
# Opens http://localhost:8888
```
