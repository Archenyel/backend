const express = require("express");
const admin = require("firebase-admin");
const cors = require("cors");
const bodyParser = require("body-parser");
require("dotenv").config();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const serviceAccount = JSON.parse(process.env.FIREBASE_CREDENTIALS);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();
const app = express();

const allowedOrigins = [
  "https://tu-frontend.onrender.com",
  "http://localhost:3000",
  "https://escuela-ashy.vercel.app",
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(bodyParser.json());

app.post("/registro", async (req, res) => {
  try {
    const { userName, email, password } = req.body;

    if (!userName || !email || !password) {
      return res.status(400).json({ error: "Faltan datos requeridos" });
    }

    const usersRef = db.collection("USERS");

    const [userNameSnapshot, emailSnapshot] = await Promise.all([
      usersRef.where("userName", "==", userName).get(),
      usersRef.where("email", "==", email).get()
    ]);

    if (!userNameSnapshot.empty || !emailSnapshot.empty) {
      return res.status(400).json({ error: "El usuario o email ya existe" });
    }

    const salt = await bcrypt.genSalt(10);
    const encryptedpass = await bcrypt.hash(password, salt);

    const userRef = db.collection("USERS").doc(email);
    await userRef.set({
      userName,
      email,
      password: encryptedpass,
      rol: "usuario",
    });

    res.status(200).json({ message: "Registro exitoso" });
  } catch (error) {
    console.error("Error en el registro:", error);
    res.status(500).json({ error: "Error al registrar el usuario" });
  }
});

app.post("/registerTask", async (req, res) => {
  try {
    const { task, date, userName, status } = req.body;

    if (!task || !date) {
      return res.status(400).json({ error: "Task y Date son requeridos" });
    }

    const newTaskRef = await db.collection("TASKS").add({
      userName,
      status,
      task,
      date,
      createdAt: new Date().toISOString(),
    });

    res.status(200).json({ message: "Tarea registrada", id: newTaskRef.id });
  } catch (error) {
    console.error("Error al registrar la tarea:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Faltan datos requeridos" });
    }

    const userRef = db.collection("USERS").doc(email);
    const doc = await userRef.get();

    if (!doc.exists) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const user = doc.data();

    console.log(user);

    const isMatch = await bcrypt.compare(password, user.password);
    
    if (!isMatch) {
      return res.status(401).json({ error: "Contraseña incorrecta" });
    }

    const userName = user.userName;
    const rol = user.rol;
    const grupo = user.grupo;

    //const token = jwt.sign({ id: email }, "secreto_super_seguro", { expiresIn: "10m" });

    return res.status(200).json({ message: "Login exitoso", userName, rol, grupo });
  } catch (error) {
    console.error("Error en el inicio de sesión:", error);
    res.status(500).json({ error: "Error al iniciar sesión" });
  }
});

app.get("/tasks", async (req, res) => {
  try {
    const user = req.headers.authorization?.split(" ")[1];
    if (!user) {
      return res.status(401).json({ error: "Usuario no autorizado" });
    }

    const tasksRef = await db
      .collection("TASKS")
      .where("userName", "==", user)
      .get();
    const tasks = tasksRef.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    }));

    res.json(tasks);
  } catch (error) {
    console.error("Error al obtener tareas:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

app.delete("/tasks/:id", async (req, res) => {
  try {
    const taskId = req.params.id;

    if (!taskId) {
      return res.status(400).json({ error: "El ID de la tarea es requerido" });
    }

    const taskRef = db.collection("TASKS").doc(taskId);
    const taskDoc = await taskRef.get();

    if (!taskDoc.exists) {
      return res.status(404).json({ error: "Tarea no encontrada" });
    }

    await taskRef.delete();

    res.status(200).json({ message: "Tarea eliminada correctamente" });
  } catch (error) {
    console.error("Error al eliminar la tarea:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

app.put("/updateTask/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { task, date, status } = req.body;

    const taskRef = db.collection("TASKS").doc(id);
    const doc = await taskRef.get();

    if (!doc.exists) {
      return res.status(404).json({ error: "Tarea no encontrada" });
    }

    await taskRef.update({ task, date, status });

    res.json({ message: "Tarea actualizada correctamente" });
  } catch (error) {
    res.status(500).json({ error: "Error al actualizar la tarea" });
  }
});

app.get("/users", async (req, res) => {
  try {
    const usersSnapshot = await db.collection("USERS").get();
    const users = [];

    usersSnapshot.forEach((doc) => {
      users.push({
        id: doc.id,
        ...doc.data(),
      });
    });

    res.json(users);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error fetching users from Firestore" });
  }
});

app.put("/users/:userId", async (req, res) => {
  const { userId } = req.params;
  const { rol } = req.body;

  if (!rol || !["admin", "lider", "usuario"].includes(rol)) {
    return res.status(400).json({ error: "Rol inválido" });
  }

  try {
    const userRef = db.collection("USERS").doc(userId);

    await userRef.update({ rol });

    res.status(200).json({ message: "Rol actualizado con éxito" });
  } catch (error) {
    res.status(500).json({ error: "Error al actualizar el rol" });
  }
});

app.post("/groups", async (req, res) => {
  const { groupName, createdBy } = req.body;

  if (!groupName || !createdBy) {
    return res.status(400).json({
      error: "Debe proporcionar un nombre para el grupo y el creador",
    });
  }

  try {
    const groupRef = db.collection("Groups");

    const newGroup = {
      groupName,
      createdBy,
    };

    await groupRef.add(newGroup);

    res.status(200).json({ message: "Grupo creado con éxito" });
  } catch (error) {
    console.error("Error al crear el grupo: ", error);
    res.status(500).json({ error: "Error al crear el grupo" });
  }
});

app.put("/groupChange/:userId", async (req, res) => {
  const { userId } = req.params;
  const { grupo } = req.body;

  try {
    const userRef = db.collection("USERS").doc(userId);

    await userRef.update({ grupo });

    res.status(200).json({ message: "grupo actualizado con éxito" });
  } catch (error) {
    res.status(500).json({ error: "Error al actualizar el grupo" });
  }
});

app.get("/groups", async (req, res) => {
  try {
    const snapshot = await db.collection("Groups").get();
    const groups = snapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    }));

    res.status(200).json(groups);
  } catch (error) {
    console.error("Error al obtener los grupos:", error);
    res.status(500).json({ error: "Error al obtener los grupos" });
  }
});

app.get("/usersByGroup", async (req, res) => {
  const { groupId } = req.query;

  if (!groupId) {
    return res.status(400).json({ error: "Falta el ID del grupo" });
  }

  try {
    const snapshot = await db
      .collection("USERS")
      .where("grupo", "==", groupId)
      .get();
    const users = snapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    }));

    res.status(200).json(users);
  } catch (error) {
    console.error("Error al obtener los usuarios:", error);
    res.status(500).json({ error: "Error al obtener los usuarios" });
  }
});

app.post("/assignedTask", async (req, res) => {
  const { groupId, assignedTo, taskName, dueDate, status, createdBy } =
    req.body;

  if (
    !groupId ||
    !assignedTo ||
    !taskName ||
    !dueDate ||
    !status ||
    !createdBy
  ) {
    return res.status(400).json({ error: "Todos los campos son obligatorios" });
  }

  try {
    const taskRef = db.collection("tasks");

    const newTask = {
      groupId,
      assignedTo,
      taskName,
      dueDate,
      status,
      createdBy,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    await taskRef.add(newTask);

    res
      .status(200)
      .json({ message: "Tarea asignada con éxito", task: newTask });
  } catch (error) {
    console.error("Error al asignar tarea:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

app.get("/groupTasks", async (req, res) => {
  try {
    const group = req.headers.authorization?.split(" ")[1];
    console.log("grupo" + group);
    if (!group) {
      return res.status(401).json({ error: "group no autorizado" });
    }

    const tasksRef = await db
      .collection("tasks")
      .where("groupId", "==", group)
      .get();
    const tasks = tasksRef.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    }));

    res.json(tasks);
  } catch (error) {
    console.error("Error al obtener tareas:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

app.put("/updateTaskStatus/:taskId", async (req, res) => {
  const { taskId } = req.params;
  const { status } = req.body;

  if (!status) {
    return res.status(400).json({ error: "El estatus es obligatorio" });
  }

  try {
    const taskRef = db.collection("tasks").doc(taskId);
    await taskRef.update({ status });

    res.status(200).json({ message: "Estatus actualizado con éxito" });
  } catch (error) {
    res.status(500).json({ error: "Error al actualizar el estatus" });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
