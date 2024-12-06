document.addEventListener('DOMContentLoaded', function() {
  const categoryLinks = document.querySelectorAll('.category-card');
  const categoryGroups = document.querySelectorAll('.category-group');

  categoryLinks.forEach(link => {
    link.addEventListener('click', function(event) {
      event.preventDefault();

      // Hide all category groups with transition
      categoryGroups.forEach(group => {
        group.classList.remove('visible');
        group.style.display = 'none';
      });

      // Get the target category group
      const targetCategory = document.getElementById(link.getAttribute('href').substring(1));

      // Display the selected category group with transition
      targetCategory.style.display = 'block';
      setTimeout(() => {
        targetCategory.classList.add('visible');
      }, 20); 
    });
  });
});
