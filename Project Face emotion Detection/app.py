
import os
import numpy as np
import cv2

# Import Keras 3.0
import keras
from keras import layers, models, ops
from keras.utils import to_categorical
print(f"Using Keras {keras.__version__}")

from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt

# ============================================================================
# PART 1: DATA PREPARATION AND MODEL TRAINING
# ============================================================================

class EmotionDetectionModel:
    def __init__(self):
        self.model = None
        self.emotions = ['Angry', 'Fear', 'Happy', 'Sad', 'Surprise']
        self.img_size = 48
        
    def create_cnn_model(self):
        """Create CNN model for emotion detection"""
        model = models.Sequential([
            # First Convolutional Block
            layers.Conv2D(32, (3, 3), activation='relu', input_shape=(48, 48, 1)),
            layers.BatchNormalization(),
            layers.Conv2D(32, (3, 3), activation='relu'),
            layers.BatchNormalization(),
            layers.MaxPooling2D((2, 2)),
            layers.Dropout(0.25),
            
            # Second Convolutional Block
            layers.Conv2D(64, (3, 3), activation='relu'),
            layers.BatchNormalization(),
            layers.Conv2D(64, (3, 3), activation='relu'),
            layers.BatchNormalization(),
            layers.MaxPooling2D((2, 2)),
            layers.Dropout(0.25),
            
            # Third Convolutional Block
            layers.Conv2D(128, (3, 3), activation='relu'),
            layers.BatchNormalization(),
            layers.Conv2D(128, (3, 3), activation='relu'),
            layers.BatchNormalization(),
            layers.MaxPooling2D((2, 2)),
            layers.Dropout(0.25),
            
            # Dense Layers
            layers.Flatten(),
            layers.Dense(256, activation='relu'),
            layers.BatchNormalization(),
            layers.Dropout(0.5),
            layers.Dense(128, activation='relu'),
            layers.BatchNormalization(),
            layers.Dropout(0.5),
            layers.Dense(len(self.emotions), activation='softmax')
        ])
        
        model.compile(
            optimizer='adam',
            loss='categorical_crossentropy',
            metrics=['accuracy']
        )
        
        self.model = model
        return model
    
    def load_dataset(self, dataset_path):
        """
        Load and preprocess emotion dataset
        Expected structure:
        dataset_path/
            Angry/
            Fear/
            Happy/
            Sad/
            Surprise/
        """
        X = []
        y = []
        
        for idx, emotion in enumerate(self.emotions):
            emotion_path = os.path.join(dataset_path, emotion)
            if not os.path.exists(emotion_path):
                print(f"Warning: {emotion_path} not found")
                continue
                
            for img_name in os.listdir(emotion_path):
                img_path = os.path.join(emotion_path, img_name)
                try:
                    img = cv2.imread(img_path, cv2.IMREAD_GRAYSCALE)
                    img = cv2.resize(img, (self.img_size, self.img_size))
                    X.append(img)
                    y.append(idx)
                except Exception as e:
                    print(f"Error loading {img_path}: {e}")
        
        X = np.array(X).reshape(-1, self.img_size, self.img_size, 1)
        X = X / 255.0  # Normalize
        y = to_categorical(y, len(self.emotions))
        
        return X, y
    
    def augment_data(self, X, y):
        """Manual data augmentation"""
        augmented_X = []
        augmented_y = []
        
        for img, label in zip(X, y):
            # Original
            augmented_X.append(img)
            augmented_y.append(label)
            
            # Horizontal flip
            flipped = np.fliplr(img)
            augmented_X.append(flipped)
            augmented_y.append(label)
            
            # Small rotation
            rows, cols = img.shape[:2]
            M = cv2.getRotationMatrix2D((cols/2, rows/2), 10, 1)
            rotated = cv2.warpAffine(img.squeeze(), M, (cols, rows)).reshape(48, 48, 1)
            augmented_X.append(rotated)
            augmented_y.append(label)
        
        return np.array(augmented_X), np.array(augmented_y)
    
    def train(self, dataset_path, epochs=50, batch_size=32, use_augmentation=True):
        """Train the emotion detection model"""
        print("Loading dataset...")
        X, y = self.load_dataset(dataset_path)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        print(f"Training samples: {len(X_train)}")
        print(f"Testing samples: {len(X_test)}")
        
        # Apply data augmentation if enabled
        if use_augmentation:
            print("Applying data augmentation...")
            X_train, y_train = self.augment_data(X_train, y_train)
            print(f"Augmented training samples: {len(X_train)}")
        
        # Create model
        if self.model is None:
            self.create_cnn_model()
        
        print("\nModel Architecture:")
        self.model.summary()
        
        # Train model
        print("\nStarting training...")
        history = self.model.fit(
            X_train, y_train,
            batch_size=batch_size,
            validation_data=(X_test, y_test),
            epochs=epochs,
            verbose=1
        )
        
        # Evaluate
        test_loss, test_acc = self.model.evaluate(X_test, y_test, verbose=0)
        print(f"\nTest Accuracy: {test_acc*100:.2f}%")
        
        return history
    
    def save_model(self, filepath='emotion_model.keras'):
        """Save trained model"""
        if self.model:
            self.model.save(filepath)
            print(f"Model saved to {filepath}")
    
    def load_model(self, filepath='emotion_model.keras'):
        """Load pre-trained model"""
        self.model = keras.models.load_model(filepath)
        print(f"Model loaded from {filepath}")


# ============================================================================
# PART 2: REAL-TIME EMOTION DETECTION
# ============================================================================

class RealtimeEmotionDetector:
    def __init__(self, model_path='emotion_model.keras'):
        """Initialize real-time detector"""
        self.emotions = ['Angry', 'Fear', 'Happy', 'Neutral', 'Sad', 'Surprise']
        self.img_size = 48
        
        # Load model
        print("Loading emotion detection model...")
        self.model = keras.models.load_model(model_path)
        
        # Load Haar Cascade classifiers
        self.face_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
        )
        self.eye_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + 'haarcascade_eye.xml'
        )
        
        # Emotion colors (BGR format)
        self.emotion_colors = {
            'Angry': (0, 0, 255),      # Red
            'Fear': (128, 0, 128),     # Purple
            'Happy': (0, 255, 0),      # Green
            'Neutral': (255, 255, 255),# White
            'Sad': (255, 0, 0),        # Blue
            'Surprise': (0, 255, 255)  # Yellow
        }
    
    def preprocess_face(self, face_img):
        """Preprocess face image for prediction"""
        face_img = cv2.resize(face_img, (self.img_size, self.img_size))
        face_img = face_img / 255.0
        face_img = face_img.reshape(1, self.img_size, self.img_size, 1)
        return face_img
    
    def predict_emotion(self, face_img):
        """Predict emotion from face image"""
        processed = self.preprocess_face(face_img)
        predictions = self.model.predict(processed, verbose=0)
        emotion_idx = np.argmax(predictions[0])
        confidence = predictions[0][emotion_idx]
        return self.emotions[emotion_idx], confidence
    
    def detect_and_display(self, frame):
        """Detect faces and emotions in frame"""
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        
        # Detect faces
        faces = self.face_cascade.detectMultiScale(
            gray, scaleFactor=1.1, minNeighbors=5, minSize=(100, 100)
        )
        
        for (x, y, w, h) in faces:
            # Extract face region
            face_roi = gray[y:y+h, x:x+w]
            
            # Detect eyes in face region
            eyes = self.eye_cascade.detectMultiScale(
                face_roi, scaleFactor=1.1, minNeighbors=10
            )
            
            # Predict emotion
            emotion, confidence = self.predict_emotion(face_roi)
            color = self.emotion_colors[emotion]
            
            # Draw face rectangle
            cv2.rectangle(frame, (x, y), (x+w, y+h), color, 3)
            
            # Draw eyes
            for (ex, ey, ew, eh) in eyes:
                cv2.rectangle(frame, (x+ex, y+ey), (x+ex+ew, y+ey+eh), (0, 255, 0), 2)
            
            # Display emotion text
            text = f"{emotion}: {confidence*100:.1f}%"
            cv2.putText(frame, text, (x, y-10), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.9, color, 2)
            
            # Add eye count info
            eye_text = f"Eyes: {len(eyes)}"
            cv2.putText(frame, eye_text, (x, y+h+25),
                       cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 2)
        
        return frame
    
    def run(self):
        """Start real-time emotion detection"""
        print("Starting webcam...")
        print("Press 'q' to quit")
        
        cap = cv2.VideoCapture(0)
        
        if not cap.isOpened():
            print("Error: Cannot access webcam")
            return
        
        while True:
            ret, frame = cap.read()
            if not ret:
                print("Error: Cannot read frame")
                break
            
            # Process frame
            frame = self.detect_and_display(frame)
            
            # Display instructions
            cv2.putText(frame, "Press 'q' to quit", (10, 30),
                       cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2)
            
            # Show frame
            cv2.imshow('Emotion Detection System', frame)
            
            # Check for quit
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break
        
        cap.release()
        cv2.destroyAllWindows()
        print("Emotion detection stopped")


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main execution function"""
    print("=" * 60)
    print("FACE EMOTION DETECTION SYSTEM")
    print("=" * 60)
    
    print("\n[1] Train new model")
    print("[2] Run real-time detection")
    print("[3] Train and run")
    
    choice = input("\nEnter choice (1/2/3): ")
    
    if choice == '1':
        # Train new model
        dataset_path = input("Enter dataset path: ")
        epochs = int(input("Enter number of epochs (default 50): ") or "50")
        
        detector = EmotionDetectionModel()
        detector.train(dataset_path, epochs=epochs)
        detector.save_model('emotion_model.keras')
        
    elif choice == '2':
        # Run detection
        model_path = input("Enter model path (default: emotion_model.keras): ") or 'emotion_model.keras'
        
        if not os.path.exists(model_path):
            print(f"Error: Model file {model_path} not found!")
            print("Please train a model first (option 1)")
            return
        
        detector = RealtimeEmotionDetector(model_path)
        detector.run()
        
    elif choice == '3':
        # Train and run
        dataset_path = input("Enter dataset path: ")
        epochs = int(input("Enter number of epochs (default 30): ") or "30")
        
        # Train
        model = EmotionDetectionModel()
        model.train(dataset_path, epochs=epochs)
        model.save_model('emotion_model.keras')
        
        # Run detection
        print("\nStarting real-time detection...")
        detector = RealtimeEmotionDetector('emotion_model.keras')
        detector.run()
    
    else:
        print("Invalid choice!")


if __name__ == "__main__":
    main()