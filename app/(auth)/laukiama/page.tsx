'use client';

import Link from 'next/link';

export default function PendingApprovalPage() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="max-w-md w-full space-y-8 p-8 bg-white rounded-lg shadow-md">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-gray-900">scanit.lt</h1>
          <div className="mt-6">
            <div className="mx-auto w-16 h-16 bg-yellow-50 rounded-full flex items-center justify-center mb-4">
              <svg className="w-8 h-8 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <h2 className="text-lg font-semibold text-gray-900 mb-2">
              Paskyra laukia patvirtinimo
            </h2>
            <p className="text-gray-600 text-sm leading-relaxed">
              Jūsų registracijos prašymas gautas ir šiuo metu peržiūrimas administratoriaus.
              Kai paskyra bus patvirtinta, gausite pranešimą el. paštu.
            </p>
          </div>
          <div className="mt-8">
            <Link
              href="/login"
              className="text-blue-600 hover:text-blue-500 font-medium text-sm"
            >
              Grįžti į prisijungimą
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
