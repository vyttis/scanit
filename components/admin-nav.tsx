'use client';

import { NavLink } from '@/components/nav-link';

export function AdminNav() {
  return (
    <div className="flex items-center space-x-4 mb-6 border-b border-gray-200 pb-3">
      <NavLink href="/admin">
        Apžvalga
      </NavLink>
      <NavLink href="/admin/vartotojai">
        Vartotojai
      </NavLink>
      <NavLink href="/admin/organizacijos">
        Organizacijos
      </NavLink>
      <NavLink href="/admin/audit">
        Audito žurnalas
      </NavLink>
    </div>
  );
}
