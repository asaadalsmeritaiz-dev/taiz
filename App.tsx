/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useEffect } from 'react';
import { getSavedUser, clearAuth } from './utils/api.js';
import Login from './components/Login.tsx';
import StudentDashboard from './components/StudentDashboard.tsx';
import AdminDashboard from './components/AdminDashboard.tsx';
import { RefreshCw } from 'lucide-react';

export default function App() {
  const [user, setUser] = useState<any | null>(null);
  const [initializing, setInitializing] = useState(true);

  useEffect(() => {
    // Check if user session already exists in local state
    const savedUser = getSavedUser();
    if (savedUser) {
      setUser(savedUser);
    }
    setInitializing(false);
  }, []);

  const handleLoginSuccess = (loggedInUser: any) => {
    setUser(loggedInUser);
  };

  const handleLogout = () => {
    clearAuth();
    setUser(null);
  };

  if (initializing) {
    return (
      <div className="min-h-screen bg-[#101923] flex flex-col justify-center items-center gap-3 text-white font-sans" dir="rtl">
        <RefreshCw className="h-8 w-8 text-indigo-400 animate-spin" />
        <p className="text-xs text-[#6B7B8D] tracking-wider">جاري التحقق من شهادات الوصول إلى البوابة...</p>
      </div>
    );
  }

  if (!user) {
    return <Login onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="min-h-screen bg-[#101923]" dir="rtl">
      {user.role === 'admin' ? (
        <AdminDashboard user={user} onLogout={handleLogout} />
      ) : (
        <StudentDashboard user={user} onLogout={handleLogout} />
      )}
    </div>
  );
}
