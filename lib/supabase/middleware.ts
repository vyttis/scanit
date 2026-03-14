import { createServerClient } from '@supabase/ssr';
import { NextResponse, type NextRequest } from 'next/server';

export async function updateSession(request: NextRequest) {
  let supabaseResponse = NextResponse.next({
    request,
  });

  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll() {
          return request.cookies.getAll();
        },
        setAll(cookiesToSet) {
          cookiesToSet.forEach(({ name, value }) =>
            request.cookies.set(name, value),
          );
          supabaseResponse = NextResponse.next({
            request,
          });
          cookiesToSet.forEach(({ name, value, options }) =>
            supabaseResponse.cookies.set(name, value, options),
          );
        },
      },
    },
  );

  const {
    data: { user },
  } = await supabase.auth.getUser();

  const pathname = request.nextUrl.pathname;

  // Public auth routes — accessible without login
  const authRoutes = ['/login', '/register', '/laukiama', '/pamirsau-slaptazodi', '/naujas-slaptazodis', '/registracija-gauta'];
  const publicRoutes = ['/tikrinti', '/rezultatai'];
  const isAuthRoute = authRoutes.some(route => pathname.startsWith(route));
  const isPublicRoute = publicRoutes.some(route => pathname.startsWith(route));
  const isApiRoute = pathname.startsWith('/api');
  const isCallbackRoute = pathname.startsWith('/api/auth/callback');

  if (isCallbackRoute) {
    return supabaseResponse;
  }

  if (!user && !isAuthRoute && !isPublicRoute && !isApiRoute && pathname !== '/') {
    const url = request.nextUrl.clone();
    url.pathname = '/login';
    return NextResponse.redirect(url);
  }

  // If user is logged in, check approval status before allowing dashboard access
  if (user && !isAuthRoute && !isApiRoute && pathname !== '/') {
    const { data: profile } = await supabase
      .from('profiles')
      .select('status')
      .eq('id', user.id)
      .single();

    // Pending or rejected users get redirected to waiting page
    if (profile && (profile.status === 'pending' || profile.status === 'rejected') && pathname !== '/laukiama') {
      const url = request.nextUrl.clone();
      url.pathname = '/laukiama';
      return NextResponse.redirect(url);
    }
  }

  if (user && isAuthRoute && !pathname.startsWith('/laukiama') && !pathname.startsWith('/pamirsau-slaptazodi') && !pathname.startsWith('/naujas-slaptazodis')) {
    const url = request.nextUrl.clone();
    url.pathname = '/dashboard';
    return NextResponse.redirect(url);
  }

  return supabaseResponse;
}
