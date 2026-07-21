SHIFT AVAILABILITY BOARD — GITHUB + VERCEL + NEON DEPLOYMENT GUIDE
=====================================================================
This replaces InfinityFree entirely. No PHP, no MySQL — this version
runs on Vercel (fast, free, no ads/throttling) with a free Neon
Postgres database. GitHub is where your code lives; Vercel deploys
straight from it automatically every time you push a change.


FILES IN THIS PACKAGE
  index.html            - the website (same UI as before)
  api/roster.js         - the entire backend, as one Vercel serverless function
  package.json          - tells Vercel which two small libraries to install
  schema-postgres.sql   - run this once in Neon to create the database tables
  .gitignore            - keeps node_modules etc. out of your repo


STEP 1 — Put this code on GitHub
  1. Go to github.com and sign in (or create a free account).
  2. Click the "+" in the top right -> "New repository".
  3. Name it something like "roster-board". Keep it Public or Private,
     either is fine. Don't add a README/gitignore/license (we already
     have one). Click "Create repository".
  4. On the next page, use "uploading an existing file" (the text link
     under the git-command instructions) — this lets you drag and drop
     files without needing git installed.
  5. Drag in: index.html, api/roster.js (yes, keep it inside an "api"
     folder — GitHub's upload box supports dragging a folder), package.json,
     and .gitignore. Commit the changes.

  (If you're comfortable with git/command line instead, the usual
  `git init`, `git add .`, `git commit`, `git push` works too — either
  way is fine, this is just the no-install path.)


STEP 2 — Deploy it on Vercel
  1. Go to vercel.com and sign up free using your GitHub account (this
     also connects the two automatically).
  2. Click "Add New..." -> "Project".
  3. Find and import the "roster-board" repository you just created.
  4. Framework Preset: leave it as "Other" (no build step needed).
  5. Click "Deploy". It should finish in under a minute. You'll get a
     URL like https://roster-board-yourname.vercel.app — that's your
     new site, though it won't work yet until Steps 3 and 4 are done.


STEP 3 — Add the free Neon database
  1. In your Vercel project, click the "Storage" tab.
  2. Click "Create Database" (or "Browse Marketplace" depending on the
     current Vercel layout) and choose "Neon" (Postgres).
  3. Follow the prompts to create a free Neon project and connect it —
     Vercel automatically adds a DATABASE_URL environment variable to
     your project for you. You don't need to copy/paste any connection
     string yourself.


STEP 4 — Add your own secret key
  1. In your Vercel project, go to Settings -> Environment Variables.
  2. Add a new variable:
       Name:  ADMIN_SESSION_SECRET
       Value: any long random string you make up — e.g. mash your
              keyboard for 30+ characters, or use a phrase like
              "karabar-kaleen-roster-2026-secret-key-xyz123"
  3. Apply it to Production (and Preview/Development if you want).
  4. Go to the "Deployments" tab and click "Redeploy" on the latest
     deployment so it picks up the new variable.

  (This key signs the admin login session cookie. Keep it private —
  anyone who has it could forge an admin session. It's not something
  you'll ever need to type into the app itself.)


STEP 5 — Create the database tables
  1. Back in Vercel's Storage tab, click through to open your Neon
     project (there's usually a link straight to the Neon dashboard).
  2. In Neon, open the "SQL Editor".
  3. Paste in the entire contents of schema-postgres.sql and run it.
  4. You should now have 5 tables: departments, locations, staff,
     availability, settings — with a test login (code TEST01) seeded
     under Karabar.


STEP 6 — Test it
  1. Visit your Vercel URL.
  2. "I'm Staff" -> log in with TEST01 -> submit availability.
  3. "I'm Admin" -> log in with admin123 -> check the Availability tab
     shows the test submission -> go to Settings and change the
     password immediately.
  4. Delete the "Test Staff" account from Admin -> Staff once you've
     added your real team.


HOW UPDATES WORK NOW
  Any time you want to change something, just edit the files in your
  GitHub repo (either by uploading a replacement file through the
  GitHub website, or via git push if you're using the command line).
  Vercel automatically redeploys within a few seconds of any change —
  no manual re-upload step like InfinityFree required.


WHY THIS IS FASTER
  - Vercel serves the site from a global CDN — no shared-host
    throttling or injected ads.
  - Neon's free tier keeps the database "asleep" when nobody's using
    it and wakes up in well under a second on the next request — in
    practice this feels close to instant for a small team roster.
  - The admin session now uses a signed cookie instead of a
    server-side session file, which was the actual source of some of
    the earlier login flakiness on shared hosting.


TROUBLESHOOTING
  - Visiting your site shows a 500 or a database error -> double
    check Step 3 (Neon connected) and Step 5 (tables created) both
    happened.
  - "Not authorized" right after logging in as admin -> check
    ADMIN_SESSION_SECRET is set (Step 4) and that you redeployed after
    adding it.
  - Changes you make on GitHub don't seem to appear -> check the
    Vercel "Deployments" tab; it should show a new deployment for each
    push. Click it to see build logs if something failed.
