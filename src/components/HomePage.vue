<template>
  <div class="main">
    <header :class="{ scrolled: isScrolled }">
      <nav>
        <div class="container">
          <a href="#home" class="logo">RaiseFPS</a>
          <button class="menu-toggle" @click="toggleMenu" aria-label="Toggle Menu">
            <i class="fas fa-bars"></i>
          </button>
          <ul class="nav-links" :class="{ active: menuVisible }">
            <li v-for="link in navLinks" :key="link.text">
              <a :href="link.href" @click="onNavLinkClick">{{ link.text }}</a>
            </li>
          </ul>
        </div>
      </nav>
    </header>

    <main>
      <section id="home" class="glowne">
        <div class="overlay"></div>
        <div class="container">
          <div class="main-content">
            <h3>Optymalizacja Gier</h3>
            <h1>RaiseFPS</h1>
            <p>Wydobądź pełen potencjał swoich gier dzięki narzędziu, które poprawi wydajność Twojego systemu Windows!</p>
            <a href="#"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=25&duration=4000&pause=1000¢er=true&width=550&lines=Witaj+na+oficjalnej+stronie+RaiseFPS!" alt="Typing SVG" /></a>
            <hr>
            <div class="glowne-buttons">
              <a href="#download" id="download"><i class="fas fa-download"></i> DOWNLOAD</a>
              <a href="#cennik" id="cennik">CENNIK</a>
            </div>
          </div>
          <a href="#features" class="scroll-down" aria-label="Scroll down">
            <i class="fas fa-arrow-down"></i>
          </a>
        </div>
      </section>

      <section id="features" class="features">
        <div class="container">
          <div class="section-header">
            <h2>Funkcje RaiseFPS</h2>
          </div>

          <div class="feature-card">
            <h3>Optymalizacja Systemu</h3>
            <p class="feature-description">Dostosuj ustawienia systemu Windows, aby zredukować tłumienie wydajności i zwiększyć stabilność gier.</p>
          </div>

          <div class="feature-card">
            <h3>Wydajność Gier</h3>
            <p class="feature-description">Uzyskaj więcej klatek na sekundę (FPS) podczas grania dzięki zaawansowanym technikom optymalizacji.</p>
          </div>

          <div class="feature-card">
            <h3>Łatwy w Użyciu</h3>
            <p class="feature-description">Intuicyjny interfejs użytkownika, który umożliwia szybkie wprowadzenie niezbędnych zmian w kilka minut.</p>
          </div>
        </div>
      </section>

      <section id="about" class="about">
        <div class="container">
          <div class="section-header">
            <h2>O Narzędziu</h2>
          </div>
          <div class="about-content">
            <div class="about-text">
              <h3>Najlepsza Optymalizacja Gier W Polsce</h3>
              <p><b>RaiseFPS</b> to narzędzie dedykowane wszystkim graczom, którzy pragną uzyskać lepszą wydajność gier na komputerach z systemem Windows. Skorzystaj z naszych zaawansowanych ustawień, aby poprawić swoje doświadczenie gamingowe.</p>
              <a href="#download" id="download">DOWNLOAD</a>
            </div>
            <div class="about-image">
              <img src="https://i.imgur.com/TAzbtTo.png" alt="RaiseFPSTool" />
            </div>
          </div>
        </div>
      </section>

      <section id="kontakt" class="kontakt">
        <div class="container">
          <div class="section-header">
            <h2>Skontaktuj się z Nami</h2>
            <p>Masz pytania lub potrzebujesz pomocy? Napisz do nas!</p>
          </div>

          <div class="kontakt-container">
            <div class="kontakt-info">
              <div class="info">
                <div class="info-item">
                  <div>
                    <p class="info-title">ㅤㅤㅤ<i class="fas fa-envelope"></i> E-mailㅤㅤㅤ</p>
                    <p class="info-detail"><a href="mailto:monteyszef@gmail.com">monteyszef@gmail.com</a></p>
                    <p class="info-detail"><a href="mailto:bartolinski6@gmail.com">bartolinski6@gmail.com</a></p>
                  </div>
                </div>
                <div class="info-item">
                  <div>
                    <p class="info-title">ㅤㅤㅤ<i class="fab fa-discord"></i> Discordㅤㅤㅤ</p>
                    <p class="info-detail"><a href="https://discord.gg/U4UMUFyCHH" target="_blank">Support RaiseFPS</a></p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>
    </main>

    <footer>
      <div class="container">
        <div class="footer-top">
          <div></div><div></div>
          <div class="footer-nav">
            <a href="#home">Strona Główna</a>
            <a href="#features">Funkcje</a>
            <a href="#about">O Narzędziu</a>
            <a href="#kontakt">Kontakt</a>
          </div>
          <div class="social-links">
            <a href="https://github.com/mOnteySZEF" target="_blank" aria-label="GitHub">
              <i class="fab fa-github"></i>
            </a>
            <a href="https://instagram.com/monteyszef" target="_blank" aria-label="Instagram">
              <i class="fab fa-instagram"></i>
            </a>
            <a href="https://www.youtube.com/channel/@mOnteySZEF" target="_blank" aria-label="YouTube">
              <i class="fab fa-youtube"></i>
            </a>
            <a href="https://discord.com/users/775425961197043792" target="_blank" aria-label="Discord">
              <i class="fab fa-discord"></i>
            </a>
          </div>
        </div>
        <div class="footer-bottom">
          <p>Made with ❤️ | © 2025 Copyright</p>
        </div>
      </div>
    </footer>
  </div>
</template>

<script>
export default {
  name: 'HomePage',
  data() {
    return {
      menuVisible: false,
      isScrolled: false,
      navLinks: [
        { text: 'Strona Główna', href: '#home' },
        { text: 'Funkcje', href: '#features' },
        { text: 'O Narzędziu', href: '#about' },
        { text: 'Kontakt', href: '#kontakt' }
      ]
    };
  },
  methods: {
    toggleMenu() {
      this.menuVisible = !this.menuVisible;
    },
    onNavLinkClick(event) {
      this.menuVisible = false;
      const targetId = event.currentTarget.getAttribute('href');
      this.smoothScroll(targetId);
    },
    smoothScroll(targetId) {
      const targetElement = document.querySelector(targetId);
      if (targetElement) {
        const headerHeight = this.$el.querySelector('header').offsetHeight;
        const targetPosition = targetElement.getBoundingClientRect().top + window.scrollY - headerHeight;
        window.scrollTo({
          top: targetPosition,
          behavior: 'smooth'
        });
      }
    }
  },
  created() {
    window.addEventListener('scroll', () => {
      this.isScrolled = window.scrollY > 10;
    });

    const observerOptions = { threshold: 0.25 };
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('animate');
          observer.unobserve(entry.target);
        }
      });
    }, observerOptions);

    document.querySelectorAll('.section-header, .feature-card').forEach(el => {
      observer.observe(el);
    });
  },
  beforeUnmount() {
    window.removeEventListener('scroll', () => {
      this.isScrolled = window.scrollY > 10;
    });
  }
};
</script>

<style scoped>
  .main {
    font-family: 'Kanit', sans-serif;
    background-color: #0a0a0c;
    color: #fafafa;
    line-height: 1.6;
    min-height: 100vh;
    scroll-behavior: smooth;
  }

  .container {
    width: 100%;
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 1rem;
  }

  /* Header Styles */
  header {
    position: fixed;
    top: 0;
    width: 100%;
    z-index: 100;
    transition: background-color 0.3s ease;
  }

  header.scrolled {
    background-color: rgba(0, 0, 0, 0.8);
    backdrop-filter: blur(10px);
  }

  nav {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem 0;
  }

  nav .container {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .menu-toggle {
    display: none;
  }

  .nav-links {
    display: flex;
    list-style: none;
  }

  .nav-links li {
    margin-left: 2rem;
  }

  .nav-links a {
    color: #fafafa;
    transition: color 0.3s ease;
  }

  .nav-links a:hover {
    color: #72EBFE;
  }

  /* Typographic Styles */
  h1, h2, h3, h4, h5, h6 {
    font-weight: 700;
    line-height: 1.2;
  }

  h1 {
    font-size: 4rem;
  }

  h2 {
    font-size: 2.5rem;
    background: linear-gradient(to right bottom, #5DE150, #72EBFE, #fafafa);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    color: transparent;
  }

  h3,h4 {
    font-size: 1.5rem;
  }

  p {
    margin-bottom: 1rem;
  }

  a {
    color: inherit;
    text-decoration: none;
  }

  /* Button Styles */
  #download {
    background-color: #72EBFE;
    color: black;
    border: 2px solid #72EBFE;
    padding: 12px 20px;
    border-radius: 7px;
    text-decoration: none;
    font-weight: bold;
    cursor: pointer;
    transition: background-color 0.3s ease, color 0.3s ease;
  }

  #download:hover {
    background-color: transparent;
    border: 2px solid #72EBFE;
    color: #72EBFE;
  }
  #cennik {
    background-color: transparent;
    color: white;
    border: 2px solid #72EBFE;
    padding: 10px 20px;
    border-radius: 7px;
    font-weight: bold;
    cursor: pointer;
    transition: background-color 0.3s ease, color 0.3s ease;
  }

  #cennik i {
    margin-right: 5px;
    color: #72EBFE;
  }

  #cennik:hover {
    color: #72EBFE;
  }

  .about-content {
    display: flex;
    align-items: center; 
    justify-content: space-between; 
    flex-wrap: wrap; 
  }

  .about-text {
    flex: 1; 
    margin-right: 2rem;
    text-align: left;
  }
  .about-text h3 {
    font-size: 2.6rem;
    margin-bottom: 1rem;
    max-width: 500px;
  }
  .about-text p {
    font-size: 1.25rem;
    color: #d4d4d4;
    margin-bottom: 2rem;
    max-width: 500px;
  }

  .about-image {
    flex: 1;
    margin-left: 5rem;
  }

  .about-image img {
    max-width: 100%;
    height: auto; 
    width: 75%;
    border-radius: 0.75rem;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
  }

  .glowne {
    position: relative;
    min-height: 100vh;
    display: flex;
    align-items: center;
    padding: 5rem 0;
    background: linear-gradient(to bottom right, rgba(76, 29, 149, 0.1), #0a0a0c);
  }

  .main-content hr {
    width: 80%;
    border: 1px solid white;
    margin: 20px auto;
  }

  .glowne .overlay {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-image: url('https://i.imgur.com/bGYT728.jpeg');
    background-size: cover;
    background-position: center;
    opacity: 0.1;
    z-index: 0;
  }

  .main-content {
    position: relative;
    z-index: 1;
    text-align: center;
    max-width: 800px;
    margin: 0 auto;
  }

  .glowne h3 {
    color: #72EBFE;
    margin-bottom: 1rem;
  }

  .glowne p {
    font-size: 1.25rem;
    color: #d4d4d4;
    margin-bottom: 2rem;
    max-width: 600px;
    margin-left: auto;
    margin-right: auto;
  }

  .glowne-buttons {
    display: flex;
    justify-content: center;
    gap: 1rem;
    margin-top: 2rem;
  }

  .scroll-down {
    position: absolute;
    bottom: 2rem;
    left: 50%;
    transform: translateX(-50%);
    color: #72EBFE;
    animation: bounce 2s infinite;
  }

  @keyframes bounce {
    0%, 20%, 50%, 80%, 100% {
      transform: translateY(0) translateX(-50%);
    }
    40% {
      transform: translateY(-30px) translateX(-50%);
    }
    60% {
      transform: translateY(-15px) translateX(-50%);
    }
  }

  section {
    padding: 5rem 0;
  }

  .section-header {
    text-align: center;
    margin-bottom: 4rem;
  }

  .feature-card {
    background-color: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 0.75rem;
    padding: 1.5rem;
    margin-bottom: 2rem;
    backdrop-filter: blur(12px);
    transition: border-color 0.3s ease;
  }

  .feature-card:hover {
    border-color: #72EBFE;
  }

  .feature-card h3 {
    font-size: 1.5rem;
    margin-bottom: 0.5rem;
  }

  .feature-description {
    color: #d4d4d4;
    margin-bottom: 1rem;
  }

  .about {
    background: linear-gradient(to bottom right, #0a0a0c, rgba(29, 131, 149, 0.05), #0a0a0c);
  }

  .kontakt {
    background: linear-gradient(to top, rgba(0, 0, 0, 0.5), rgba(29, 111, 149, 0.05));
  }

  .kontakt-container {
    display: flex;
    justify-content: center;
    padding: 0.25rem;
  }

  .kontakt-info {
    background-color: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 0.75rem;
    padding: 1rem;
    backdrop-filter: blur(12px);
    transition: border-color 0.3s ease;
    margin-bottom: 2rem;
  }

  .info {
    margin: 50px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
}

  .info-item {
    display: flex;
    align-items: center;
    margin-bottom: 1.5rem;
  }
  .info-item p a:hover {
    color: #fafafa;
  }
  .info-title {
    font-weight: 550;
    margin: 1rem auto;
    border: 2px solid rgba(255, 255, 255, 0.1);
    color: white;
    background-color: rgba(255, 255, 255, 0.05);  
    backdrop-filter: blur(12px);
    border-radius: 5px;
    padding: 10px;
    text-align: center;
    transition: border-color 0.3s ease;
  }

  .info-detail {
    color: #72EBFE;
    font-size: 0.875rem;
    margin-top: 0.30rem;
    text-align: center;
    transition: color 0.3s ease;
    text-decoration: underline;
  }

  footer {
    background-color: rgba(0, 0, 0, 0.5);
    border-top: 1px solid rgba(255, 255, 255, 0.1);
    padding: 3rem 0 2rem;
  }

  .footer-top {
    display: flex;
    justify-content: space-between;
    align-items: center;
    text-align: center;
    margin-bottom: 2rem;
  }

  .footer-nav {
    display: flex;
    gap: 1.5rem;
  }

  .footer-nav a {
    color: #a1a1a1;
    transition: color 0.3s ease;
  }

  .footer-nav a:hover {
    color: #72EBFE;
  }

  .social-links {
    display: flex;
    gap: 1rem;
  }

  .social-links a {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 2.5rem;
    height: 2.5rem;
    border-radius: 50%;
    color: #a1a1a1;
    transition: all 0.3s ease;
  }

  .social-links a:hover {
    background-color: rgba(255, 255, 255, 0.1);
    color: #72EBFE;
  }

  .footer-bottom {
    border-top: 1px solid rgba(255, 255, 255, 0.1);
    padding-top: 2rem;
    text-align: center;
    color: #717171;
    font-size: 0.875rem;
  }

  .footer-bottom p:first-child {
    margin-bottom: 0.5rem;
  }

  @media (max-width: 768px) {
    h1 {
      font-size: 2.5rem;
    }

    h2 {
      font-size: 2rem;
    }

    .glowne-buttons {
      flex-direction: column;
      align-items: center;
    }

    .glowne-buttons .btn {
      width: 100%;
      max-width: 300px;
      margin-bottom: 1rem;
    }

    .menu-toggle {
      display: block;
      background: none;
      border: none;
      color: white;
      font-size: 1.5rem;
      cursor: pointer;
    }

    .nav-links {
      display: none;
    }

    .nav-links.active {
      display: flex;
      flex-direction: column;
      position: absolute;
      top: 100%;
      left: 0;
      width: 100%;
      background: rgba(0, 0, 0, 0.95);
    }

    .footer-top {
      flex-direction: column;
      gap: 1.5rem;
    }
  }

  @media (max-width: 480px) {
    .feature-card {
      margin: 1rem 0;
    }
  }
</style>