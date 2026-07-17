# ASCEND Waitlist — Vercel + Supabase

## Deploy

1. Upload every file in this folder to the root of your GitHub repository.
2. In Vercel, import the GitHub repository and choose **Other** as the framework preset.
3. Connect your Supabase integration to the Vercel project.
4. In Vercel > Project Settings > Environment Variables, confirm one of these exists:
   - `POSTGRES_URL` (preferred when automatically added)
   - `DATABASE_URL`
   - `SUPABASE_DB_URL`
5. Add these private variables for Production, Preview, and Development:
   - `ADMIN_KEY` — a long random password
   - `IP_SALT` — another long random value
6. Redeploy the latest commit.
7. Open `/api/health`. It should return `{"ok":true}`.
8. Test the homepage with a real email.

The `subscribers` table and indexes are created automatically on the first API request.

## Admin

`https://YOUR-DOMAIN/admin?key=YOUR_ADMIN_KEY`

The admin page includes totals and CSV export. Keep the URL and key private.
