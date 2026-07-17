# ASCEND Studios Waitlist

Minimal animated waitlist deployed on Vercel with Supabase/Postgres storage, referral links, an admin dashboard, and CSV export.

Required Vercel environment variables:

- `DATABASE_URL` or `POSTGRES_URL`
- `ADMIN_KEY`
- `IP_SALT`

After deployment, test `/api/health`. The private dashboard is `/admin?key=YOUR_ADMIN_KEY`.
