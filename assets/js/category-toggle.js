document.addEventListener('DOMContentLoaded', function() {
  const categoryLinks = document.querySelectorAll('.category-card');
  const categoryGroups = document.querySelectorAll('.category-group');

  categoryLinks.forEach(link => {
    link.addEventListener('click', function(event) {
      event.preventDefault();

      // Get the target category group
      const targetCategory = document.getElementById(link.getAttribute('href').substring(1));

      // Check if the target category is already visible
      if (targetCategory.classList.contains('visible')) {
        // If visible, hide the category group with a reverse transition
        targetCategory.classList.remove('visible');
        targetCategory.style.display = 'none';

        // Optionally, you can add a slight delay before hiding to see the reverse effect
        setTimeout(() => {
          targetCategory.style.opacity = 0;
          targetCategory.style.transform = 'scale(0.9)';
        }, 300); // Delay the reverse animation for smooth transition
      } else {
        // Hide all category groups with transition
        categoryGroups.forEach(group => {
          group.classList.remove('visible');
          group.style.display = 'none';
        });

        // Display the selected category group with transition
        targetCategory.style.display = 'block';
        setTimeout(() => {
          targetCategory.classList.add('visible');
          targetCategory.style.opacity = 1;
          targetCategory.style.transform = 'scale(1)';
        }, 20);
      }
    });
  });
});
