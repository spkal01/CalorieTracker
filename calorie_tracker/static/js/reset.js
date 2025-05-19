function resetUpload() {
    const uploadContainer = document.getElementById('upload-container');
    const resultContainer = document.getElementById('result-container');
    const imageContainer = document.getElementById('image-container');

    if (uploadContainer) {
        uploadContainer.classList.remove('hidden');
        uploadContainer.innerHTML = `
            <form action="/upload" method="POST" enctype="multipart/form-data" class="space-y-6">
                <div>
                    <label class="block text-sm font-medium text-zinc-300 mb-1">Upload Image</label>
                    <input type="file" name="file" accept="image/*"
                           class="block w-full bg-zinc-900 border border-zinc-700 text-zinc-100 file:bg-zinc-700 file:text-zinc-100 file:rounded file:border-none file:px-3 file:py-2 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                <button type="submit"
                        class="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded transition">
                    Upload & Analyze
                </button>
            </form>
        `;
    }

    if (resultContainer) {
        resultContainer.style.marginTop = '0'; // Align to the top
    }

    if (imageContainer) {
        imageContainer.remove();
    }
}