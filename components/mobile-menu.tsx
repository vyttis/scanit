'use client';

import { useState } from 'react';
import { NavLink } from '@/components/nav-link';
import { LogoutButton } from '@/components/logout-button';

interface MobileMenuProps {
  navItems: { href: string; label: string }[];
  isSuperadmin: boolean;
  userEmail: string;
  userRole: string | null;
}

export function MobileMenu({ navItems, isSuperadmin, userEmail, userRole }: MobileMenuProps) {
  const [open, setOpen] = useState(false);

  const roleLabel = userRole === 'superadmin' ? 'Superadminas' : userRole === 'admin' ? 'Administratorius' : 'Stebėtojas';

  return (
    <>
      <button
        onClick={() => setOpen(!open)}
        className="inline-flex items-center justify-center p-2 rounded-md text-gray-600 hover:text-gray-900 hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
        aria-expanded={open}
        aria-label={open ? 'Uždaryti meniu' : 'Atidaryti meniu'}
      >
        {open ? (
          <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        ) : (
          <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        )}
      </button>

      {open && (
        <div className="absolute top-16 left-0 right-0 bg-white border-b border-gray-200 shadow-lg z-50 md:hidden">
          <div className="px-4 py-3 border-b border-gray-100">
            <p className="text-sm text-gray-500 truncate">{userEmail}</p>
            {userRole && (
              <span className="text-xs bg-gray-100 text-gray-600 px-2 py-0.5 rounded mt-1 inline-block">
                {roleLabel}
              </span>
            )}
          </div>
          <div className="px-4 py-2 space-y-1">
            {navItems.map((item) => (
              <div key={item.href} className="py-2" onClick={() => setOpen(false)}>
                <NavLink href={item.href}>
                  {item.label}
                </NavLink>
              </div>
            ))}
            {isSuperadmin && (
              <div className="py-2" onClick={() => setOpen(false)}>
                <NavLink href="/admin">
                  Administravimas
                </NavLink>
              </div>
            )}
          </div>
          <div className="px-4 py-3 border-t border-gray-100">
            <LogoutButton />
          </div>
        </div>
      )}
    </>
  );
}
