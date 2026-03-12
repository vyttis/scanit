'use client';

import { Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';

function RegistracijaGautaContent() {
  const searchParams = useSearchParams();
  const name = searchParams.get('name') ?? '';
  const org = searchParams.get('org') ?? '';
  const email = searchParams.get('email') ?? '';

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="max-w-md w-full p-8 bg-white rounded-lg shadow-md">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-gray-900 mb-2">scanit.lt</h1>
          <div className="mx-auto w-16 h-16 bg-green-50 rounded-full flex items-center justify-center my-6">
            <svg className="w-8 h-8 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
          </div>
          <h2 className="text-lg font-semibold text-gray-900 mb-4">
            Registracija sėkmingai gauta
          </h2>
          {name && (
            <p className="text-gray-600 text-sm mb-2">
              <strong>{name}</strong>, dėkojame už registraciją{org ? ` iš ${org}` : ''}.
            </p>
          )}
          <p className="text-gray-600 text-sm mb-4">
            Jūsų registracijos prašymas sėkmingai pateiktas. Administratorius
            peržiūrės Jūsų paraišką ir gausite pranešimą el. paštu
            {email ? <> adresu <strong>{email}</strong></> : ''}.
          </p>
          <div className="bg-blue-50 border border-blue-200 rounded-md p-3 mb-6">
            <p className="text-xs text-blue-800">
              Vidutinis patvirtinimo laikas — iki 1 darbo dienos.
            </p>
          </div>
          <Link
            href="/login"
            className="inline-block px-6 py-2 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700"
          >
            Grįžti į prisijungimą
          </Link>
        </div>
      </div>
    </div>
  );
}

export default function RegistracijaGautaPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-gray-500">Kraunama...</div>
      </div>
    }>
      <RegistracijaGautaContent />
    </Suspense>
  );
}
