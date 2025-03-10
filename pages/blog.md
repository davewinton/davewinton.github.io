---
layout: page
title: Blog
permalink: /blog/
feature-img: "assets/img/pexels/KeyboardDark.jpg"
#hide: true
---

# Pinned Posts
<ul>
  {% for post in site.posts %}
    {% if post.tags contains "pinned" %}
      <li>
        <a href="{{ post.url }}">{{ post.title }}</a> - {{ post.date | date: "%B %d, %Y" }}
      </li>
    {% endif %}
  {% endfor %}
</ul>

## Blog Categories
<!-- Blog Categories -->
<div class="category-cards-row">
  {% for category in site.categories %}
  <a href="#{{ category[0] | slugify }}" class="category-card" data-category="{{ category[0] }}">
    <h3>{{ category[0] | capitalize }}</h3>
    <p>{{ category[1] | size }} posts</p>
  </a>
  {% endfor %}
</div>

<!-- Posts by Category -->
{% for category in site.categories %}
<div id="{{ category[0] | slugify }}" class="category-group" style="display:none;">
  <h2 class="category-title">Latest Posts from <span class="category-name">{{ category[0] | capitalize }}</span></h2>
  <div class="category-posts">
    {% for post in category[1] %}
    <a href="{{ post.url | relative_url }}" class="category-post-link">
      <div class="post-card">
        <div class="post-card-content">
          <div class="post-header">
            <span class="post-title">{{ post.title }}</span>
            <span class="post-date">{{ post.date | date: '%b %-d, %Y' }}</span>
          </div>
          <p class="post-excerpt">{{ post.excerpt }}</p>
          <div class="post-tags">
            {% for tag in post.tags %}
            <a href="/tags/#{{ tag }}" class="tag">{{ tag }}</a>
            {% endfor %}
          </div>
        </div>
      </div>
    </a>
    {% endfor %}
  </div>
</div>
{% endfor %}
