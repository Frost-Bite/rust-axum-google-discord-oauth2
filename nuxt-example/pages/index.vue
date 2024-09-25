<template>
    <div>
      <div v-if="loading">
        <p>Loading...</p>
      </div>
      <div v-else>
        <div v-if="user">
          <h1>Welcome, {{ user.username }} - {{ user.email }}</h1>
          <button @click="logout">Logout</button>
        </div>
        <div v-else>
          <h1>You are not logged in</h1>
          <button @click="login">Login with Discord</button><br />
          <button @click="loginGoogle">Login with Google</button>
        </div>
      </div>
    </div>
  </template>

  <script setup>
  import { ref, onMounted } from 'vue';

  const user = ref(null);
  const loading = ref(true);

  const login = () => {
    window.location.href = 'http://127.0.0.1:3000/auth/discord';
  };

  const loginGoogle = () => {
  window.location.href = 'http://127.0.0.1:3000/auth/google';
};

  const logout = async () => {
    await fetch('http://127.0.0.1:3000/logout', {
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
      },
    });
    user.value = null;
  };

  const checkSession = async () => {
    try {
      const res = await fetch('http://127.0.0.1:3000/', {
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
      });

      if (res.ok) {
        const userData = await res.json();
        if (userData && userData.username) {
          user.value = userData;
        } else {
          user.value = null;
        }
      } else {
        console.error('Failed to fetch session, status:', res.status);
        user.value = null;
      }
    } catch (error) {
      console.error('Failed to fetch session', error);
      user.value = null;
    } finally {
      loading.value = false;
    }
  };

  onMounted(() => {
    checkSession();
  });
  </script>
