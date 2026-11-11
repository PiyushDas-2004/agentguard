# Putting AgentGuard online: a step-by-step guide for beginners

This guide takes you from "the code is on GitHub" to "people can use AgentGuard in their
browser". No programming or command line is needed: everything happens in your web browser,
on **GitHub** and on **Render** (the hosting company).

**Time:** about 30–45 minutes, most of it waiting for the first build.
**Cost:** you can start on Render's free plan. Read [Part 6](#part-6-before-real-people-depend-on-it)
before you rely on it, because the free database is deleted after 30 days.

> **Tip:** Render changes its website from time to time. If a button has a slightly different
> name than in this guide, look for the closest match. The steps stay the same.

---

## Contents

* [Part 0: How the pieces fit together (read this first)](#part-0-how-the-pieces-fit-together-read-this-first)
* [Part 1: Create a Render account and connect GitHub](#part-1-create-a-render-account-and-connect-github)
* [Part 2: Deploy AgentGuard (one Blueprint)](#part-2-deploy-agentguard-one-blueprint)
* [Part 3: First login and checks](#part-3-first-login-and-checks)
* [Part 4: Use it, and invite other people](#part-4-use-it-and-invite-other-people)
* [Part 5: Alerts and monitoring (recommended, free)](#part-5-alerts-and-monitoring-recommended-free)
* [Part 6: Before real people depend on it](#part-6-before-real-people-depend-on-it)
* [Part 7: Everyday tasks](#part-7-everyday-tasks)
* [Part 8: The remaining GitHub settings](#part-8-the-remaining-github-settings)
* [Troubleshooting](#troubleshooting)
* [Glossary](#glossary)

---

## Part 0: How the pieces fit together (read this first)

**Yes, everything connects through GitHub.** You never upload files by hand.

```
 Your code on GitHub  ──(Render reads it)──►  Render builds it  ──►  Your app on the internet
 github.com/PiyushDas-2004/agentguard          (Docker image)          https://agentguard-….onrender.com
          ▲                                                                      │
          └──────── every time new code is pushed to "main", Render ◄────────────┘
                    rebuilds and redeploys automatically
```

* **GitHub** stores the code. It's already there.
* **Render** is the hosting company. You give Render permission to *read* your GitHub repository.
* The repository contains a file named **`render.yaml`** (a "Blueprint"). It tells Render
  exactly what to create, so you don't have to configure anything by hand:
  1. **`agentguard`**: the web app people visit.
  2. **`agentguard-db`**: a PostgreSQL database that stores accounts and scan results.
* **Render generates the passwords itself** (the server's secret key and the invite code). You
  never have to invent one or type one into a file.
* **Auto-deploy:** after setup, every change pushed to the `main` branch on GitHub goes live by
  itself in a few minutes. Database updates run automatically too.

**What AgentGuard needs from you:**

* **For you to run it:** a Render account (free) and about 30 minutes.
* **For people to use it:** an invite code, which Render creates for you.
* **An AI/LLM key? No, not for you.** Scans work without one. A user who wants an extra AI
  judge pastes **their own** Gemini key into the scan form. It's used for that one scan and never
  stored.

---

## Part 1: Create a Render account and connect GitHub

### Step 1.1: Sign up with your GitHub account

1. Open **https://render.com** and click **Get Started** (or **Sign Up**).
2. Choose **GitHub** as the sign-up method. Signing up with GitHub links the two accounts
   automatically.
3. GitHub opens a page asking you to **authorize Render**. Click **Authorize**. This only lets
   Render know who you are. It doesn't give Render your code yet.
4. Render may ask a few questions (your name, how you'll use Render). Answer them and continue.
5. If Render asks you to **verify your e-mail**, open the e-mail from Render and click the link.

### Step 1.2: Let Render read the AgentGuard repository

Render needs permission to read the repository so it can build it. You'll be asked about this
in Part 2 when you pick the repository. If you'd like to do it now:

1. Open **https://github.com/apps/render/installations/new**.
2. Choose your GitHub account (**PiyushDas-2004**).
3. Under **Repository access**, choose **Only select repositories**, then pick
   **agentguard**. (Choosing "All repositories" also works, but giving access to just this one is
   safer.)
4. Click **Install** (or **Save**).

> **Why "Only select repositories"?** It follows the "least access" principle: Render can only
> see the one repository it needs.

---

## Part 2: Deploy AgentGuard (one Blueprint)

### Step 2.1: Start the Blueprint

You can use either way:

* **Easiest:** open this link while signed in to Render:
  **https://render.com/deploy?repo=https://github.com/PiyushDas-2004/agentguard**
* **Or by hand:** in the Render Dashboard click **New** (top right) → **Blueprint**. In the list
  of repositories, click **Connect** next to **agentguard**. If it isn't listed, click the option
  to configure GitHub access and repeat Step 1.2.

### Step 2.2: Fill in the Blueprint form

1. **Blueprint name:** type `agentguard` (any name works; it's only a label).
2. **Branch:** choose **main**.
3. Render reads `render.yaml` and shows what it will create. Check that you see two items:
   * a **Web Service** named **agentguard**, with plan **Free**
   * a **PostgreSQL** database named **agentguard-db**, with plan **Free**
4. **`AGENTGUARD_ADMIN_EMAILS`:** Render asks you for a value. **Type your own e-mail address**,
   the one you'll use to sign in to AgentGuard, for example `you@example.com`. This makes you the
   administrator. Render only asks for this once, during this first setup.
5. If Render asks for a **payment method**, read the summary carefully and make sure both items
   still say **Free**. Render bills only for paid plans.
6. Click **Deploy Blueprint** (it may say **Apply**).

### Step 2.3: Wait for the first build (about 5–15 minutes)

1. Render now creates the database and builds the app. You can watch progress:
   Dashboard → click **agentguard** → **Events** (a timeline) or **Logs** (live text output).
2. The first build takes the longest. Later updates are faster.
3. It's finished when the service page shows a green **Live** or **Deployed** badge. The logs end
   with lines like:

   ```
   "msg": "Running upgrade  -> 0001, Initial schema of the hosted web app ..."
   "msg": "Application startup complete."
   ```

   The first line means AgentGuard created its database tables. The second means it's running.

If the build shows **Failed**, see [Troubleshooting](#troubleshooting).

---

## Part 3: First login and checks

### Step 3.1: Open your app

1. On the **agentguard** service page, at the top, there's a link like
   **https://agentguard.onrender.com** (Render may add a few random characters, for example
   `https://agentguard-ab12.onrender.com`). This is your app's address. Click it.
2. You should see the AgentGuard start page: **"Red-team your AI agent"**.

> **Free plan:** after 15 minutes without visitors the app goes to sleep. The next visit shows a
> Render loading screen for about a minute while it wakes up. This is normal.

### Step 3.2: Find your invite code

Sign-up is invite-only, so strangers can't create accounts.

1. In Render, open the **agentguard** service → **Environment** (left menu).
2. Find **`AGENTGUARD_SIGNUP_CODE`**. Click the eye icon (or **Reveal**) and copy the value. It's
   a long random text like `n1X…=`.
3. Keep it like a password. Anyone who has it can create an account.

### Step 3.3: Create YOUR account first

> **Important:** create your own account **before** you share the invite code with anyone.
> Administrator rights belong to the e-mail address you entered in Step 2.2, so you want to be
> the first one to register that address.

1. In your app, click **Create account**.
2. **E-mail:** exactly the address you entered for `AGENTGUARD_ADMIN_EMAILS`.
3. **Password:** at least 12 characters. A short sentence is easiest to remember, for example
   `purple tiger eats 7 mangoes`.
4. **Invite code:** paste the code from Step 3.2.
5. Click **Create account**. You're now signed in, and there's an **Admin** link in the top menu.

### Step 3.4: Run the two quick checks on the Admin page

Click **Admin** in the top menu.

**Check A: Health.** The **Health** box should show **Database: PostgreSQL** and a version
number. That confirms the app is connected to its database.

**Check B: Connection check.** This confirms per-person limits (such as "max 5 sign-in
attempts") work correctly behind Render's network.

1. The box says: *AgentGuard sees your IP address as `x.x.x.x`*.
2. In another tab, search the web for **"what is my IP"** and compare.
3. **If they match:** you're done.
4. **If they don't match:** click **Details for troubleshooting**:
   * If your real IP appears next to **true-client-ip** or **cf-connecting-ip**, go to Render →
     **agentguard** → **Environment** → **Add Environment Variable**: key
     `AGENTGUARD_CLIENT_IP_HEADER`, value `True-Client-IP` (or `CF-Connecting-IP`, whichever
     showed your IP) → **Save Changes**.
   * If your IP appears inside **x-forwarded-for** but not last, set `AGENTGUARD_TRUSTED_PROXY_HOPS`
     to its position counted from the right (the last one is 1, the one before it is 2).
   * Saving restarts the app (about a minute). Then reload the Admin page and check again.

---

## Part 4: Use it, and invite other people

### Step 4.1: Scan an AI agent (yours, or a test one)

1. **Targets** → **Add a target**:
   * **Name:** anything, for example `My support bot`.
   * **Type:** *HTTP JSON API* if your agent has its own chat endpoint, or *OpenAI-compatible* if it
     speaks the OpenAI `/v1/chat/completions` format.
   * **Endpoint URL:** the agent's address. It must start with `https://`.
   * **Reply JSONPath:** where the answer is in the agent's JSON response. For
     `{"reply": "Hello"}` it's `$.reply`. Leave the default if unsure.
2. **Prove you own the endpoint.** AgentGuard refuses to attack systems that aren't yours. The
   target page shows two options. You only need one:
   * **HTTP file:** make your agent's server return the shown text at
     `https://your-agent-domain/.well-known/agentguard.txt`, or
   * **DNS:** add a TXT record named `_agentguard.your-agent-domain` with the shown text (at your
     domain provider, e.g. GoDaddy, Namecheap or Cloudflare).

   Then click **Verify**.
3. Optional: copy the **leak-detection canary** shown on the target page into your agent's
   system prompt (for example as "internal reference code: …"). AgentGuard then reports it if your
   agent ever leaks it.
4. **Run a scan** → choose categories → **Start scan**. The page updates live. A full scan takes
   a few minutes.
5. **Optional AI judge with Gemini:** create a free key at **https://aistudio.google.com/apikey**
   and paste it into the scan form's *Gemini API key* field. It's used only for that scan and
   never saved. Don't put API keys anywhere else (chat messages, e-mails, GitHub).
6. When it's done, open **Open full report**, or download **json / sarif / junit / markdown**.

### Step 4.2: Invite people

Send them two things privately (not on a public page):

1. Your app address (Step 3.1).
2. The invite code (Step 3.2).

They create their own accounts. Each person only ever sees their own targets and scans.

### Step 4.3: Change the invite code (when you want to stop new sign-ups)

Render → **agentguard** → **Environment** → `AGENTGUARD_SIGNUP_CODE` → **Edit** → type a new long
random value (at least 12 characters) → **Save Changes**. Existing accounts aren't affected.

---

## Part 5: Alerts and monitoring (recommended, free)

### Step 5.1: Get an e-mail when the site is down (UptimeRobot)

1. Create a free account at **https://uptimerobot.com**.
2. **Add New Monitor** → type **HTTP(s)**.
3. **URL:** your app address followed by `/healthz`, for example
   `https://agentguard-ab12.onrender.com/healthz`.
4. **Monitoring interval:** 5 minutes. Choose your e-mail as the alert contact. **Create Monitor**.

> **Side effect on the free plan:** checking every 5 minutes keeps the app awake, so visitors
> don't wait a minute for it to wake up. Render's free plan includes 750 hours per month, which is
> enough to keep one app awake all month.

### Step 5.2: Get an e-mail when the app has an error (Sentry)

1. Create a free account at **https://sentry.io**.
2. **Create Project** → platform **FastAPI** (or **Python**) → give it a name → **Create Project**.
3. Sentry shows a **DSN**, a web address like `https://abc123@o123.ingest.sentry.io/456`. Copy it.
   (Later you can find it under **Project Settings → Client Keys (DSN)**.)
4. Render → **agentguard** → **Environment** → **Add Environment Variable**: key `SENTRY_DSN`,
   value: the DSN → **Save Changes**.

AgentGuard removes passwords, API keys, cookies and form contents before anything is sent to
Sentry.

### Step 5.3: Where to look when something seems wrong

* **Render → agentguard → Logs:** everything the app prints. Each line has a `request_id`. Users
  can find the same id in their browser's developer tools, so you can match a complaint to a
  log line.
* **AgentGuard → Admin:** failed scans in the last 24 hours, users, and recent security events
  (sign-ins, failures, admin actions).

---

## Part 6: Before real people depend on it

The free plan is for trying things out. Before other people rely on the service:

1. **The free database is deleted after 30 days** (Render then gives a 14-day grace period).
   Upgrade it before day 30: Render → **agentguard-db** → change the instance type/plan to a paid
   one (**Upgrade**). Paid databases also get automatic **backups**, which free ones don't have.
2. **Stop the sleeping:** Render → **agentguard** → **Settings** → **Instance Type** → choose a
   paid type (e.g. **Starter**). The app then stays awake, and running scans aren't interrupted
   by a restart.
3. Check current prices at **https://render.com/pricing**.
4. **Know what isn't built in yet:**
   * **No e-mail sending.** If someone forgets their password, open **Admin** → **Reset password**
     next to their name. AgentGuard shows a one-time temporary password. Send it to them
     privately and ask them to change it under **Account → Change password**.
   * **One server only.** That's fine for a team or a small community. Scans running during a
     redeploy are stopped, and the user simply starts them again.
5. **Terms of use:** if strangers will use your service, publish simple terms that say users may
   only scan systems they own. (The ownership check enforces this technically, but a written
   rule protects you too.)

---

## Part 7: Everyday tasks

**Update the app.** Push new code to the `main` branch on GitHub. Render builds and deploys it
automatically (watch **Events**). Database changes are applied automatically when the new
version starts.

**Undo a bad update.** Render → **agentguard** → **Events** → find the previous successful deploy
→ **Rollback** (or **Redeploy**).

**Restart the app.** Render → **agentguard** → **Manual Deploy** → **Deploy latest commit** (or
**Restart service**).

**Add another administrator.** Render → **agentguard** → **Environment** →
`AGENTGUARD_ADMIN_EMAILS` → **Edit** → add the e-mail separated by a comma (e.g.
`you@example.com, colleague@example.com`) → **Save Changes**. The person must have an account
with that exact address.

**Block a user.** AgentGuard → **Admin** → **Disable** next to their name. This signs them out
everywhere and stops their scans. **Enable** undoes it.

**Use your own domain** (e.g. `agentguard.yourcompany.com`): Render → **agentguard** →
**Settings** → **Custom Domains** → **Add Custom Domain**, and follow Render's DNS instructions.
Then add the environment variable `AGENTGUARD_BASE_URL` = `https://agentguard.yourcompany.com`
(without a trailing slash) and **Save Changes**. If you skip this, forms on the new domain are
refused for security reasons (403 Forbidden).

**See how many scans people run.** AgentGuard → **Admin** → **Users** shows targets and scans
per user for the last 30 days.

---

## Part 8: The remaining GitHub settings

These three are optional, but they complete the project's public presence. All of them happen on
**https://github.com/PiyushDas-2004/agentguard**.

### 8.1: Turn on the project website (GitHub Pages)

1. Repository → **Settings** (top menu) → **Pages** (left menu).
2. **Build and deployment → Source:** **Deploy from a branch**.
3. **Branch:** `gh-pages` and folder `/ (root)` → **Save**.
4. After 1–2 minutes the site is live at **https://piyushdas-2004.github.io/agentguard/**.

### 8.2: Make the Docker images public (optional)

Only needed if other people should be able to `docker pull` the images.

1. Open your GitHub profile → **Packages** tab.
2. Click **agentguard-web** → **Package settings** (right side) → **Danger Zone** →
   **Change visibility** → **Public** → type the name to confirm.
3. Repeat for **agentguard** and **agentguard-demo** if you want.

### 8.3: Publish the v1.0.0 release

1. Repository → **Releases** (right sidebar) → **Draft a new release** (or **Create a new release**).
2. **Choose a tag** → type `v1.0.0` → **Create new tag: v1.0.0 on publish**. Target: `main`.
3. **Release title:** `AgentGuard 1.0.0`.
4. **Description:** copy the `## [1.0.0]` section from
   [CHANGELOG.md](../CHANGELOG.md).
5. **Publish release**.

---

## Troubleshooting

| What you see | What it means / what to do |
|---|---|
| Build **Failed** in Render | Open **Logs** and scroll to the first red/`error` line. Most often a temporary network problem: click **Manual Deploy → Deploy latest commit** to retry. If it fails again, copy the error lines into a GitHub issue. |
| Logs say `insecure or invalid web settings: …` | A required setting is missing or too weak. The message names it. For example, if `AGENTGUARD_SECRET_KEY` is missing, add it under **Environment** with **Generate** (or 40+ random characters). |
| Page shows **"Forbidden"** when submitting a form | Usually a custom domain without `AGENTGUARD_BASE_URL` (see Part 7). Otherwise reload the page and try again (the form was open too long). |
| **"Invalid invite code."** | Copy the code again from **Environment**: it's long, and the `=` at the end belongs to it. |
| **"Too many sign-in attempts"** | Wait 15 minutes. If everyone sees this, do the *Connection check* in Step 3.4. |
| Target verification fails | Open `https://your-agent-domain/.well-known/agentguard.txt` in your browser. It must show exactly the text from the target page, nothing else. For DNS, changes can take up to an hour to spread. |
| Scan **failed** with "time limit" | The agent answered too slowly. Choose fewer categories, or ask the operator to raise `AGENTGUARD_MAX_SCAN_MINUTES`. |
| Scan **failed** after "server restart" | The app restarted during the scan (redeploy, or the free plan going to sleep). Start the scan again. |
| Site takes ~1 minute to open | Free plan sleeping. Normal. Use the uptime monitor (Part 5.1) or a paid instance. |
| Render e-mails "database will expire" | Free database limit. See Part 6, step 1. |

---

## Glossary

* **Repository (repo):** the folder with all the project's code, on GitHub.
* **Branch `main`:** the main version of the code. Render deploys what's on `main`.
* **Blueprint / `render.yaml`:** a recipe file telling Render what to create.
* **Web Service:** a program running on Render that answers web requests (your app).
* **PostgreSQL (Postgres):** the database where accounts and results are stored.
* **Environment variable:** a named setting (like `AGENTGUARD_SIGNUP_CODE`) that Render gives to
  the app. Secrets live here, never in the code.
* **Deploy:** putting a new version of the app online.
* **Invite code:** the shared password needed to create an account.
* **Endpoint:** the web address of an AI agent's API.
* **DSN (Sentry):** the address the app uses to send error reports to your Sentry project.
