import express from "express";
import contactsController from "../../controller/contactsController.js";
import Joi from "joi";
import auth from "../../middlewares/auth.js";

const contactSchema = Joi.object({
  name: Joi.string().min(3).required(),
  email: Joi.string().email().required(),
  phone: Joi.string()
    .pattern(new RegExp("^[0-9]{3}-[0-9]{3}-[0-9]{4}$"))
    .required(),
});

const favoriteSchema = Joi.object({
  favorite: Joi.boolean().required(),
});

const router = express.Router();
const STATUS_CODES = {
  success: 200,
  created: 201,
  deleted: 204,
  notFound: 404,
  error: 500,
};

// GET localhost:3000/api/contacts
router.get("/", async (req, res) => {
  try {
    const contacts = await contactsController.listContacts();
    res
      .status(STATUS_CODES.success)
      .json({ message: "Lista a fost returnata cu succes", data: contacts });
  } catch (error) {
    res.status(STATUS_CODES.error).json({ message: `${error}` });
  }
});

// GET localhost:3000/api/contacts/:id
router.get("/:id", async (req, res) => {
  try {
    const contact = await contactsController.getContactById(req.params.id);
    if (!contact) {
      res
        .status(STATUS_CODES.notFound)
        .json({ message: "Contactul nu a fost gasit" });
      return;
    }
    res
      .status(STATUS_CODES.success)
      .json({ message: "Contactul a fost returnat cu succes", data: contact });
  } catch (error) {
    res.status(STATUS_CODES.error).json({ message: `${error}` });
  }
});

// POST localhost:3000/api/contacts/
router.post("/", async (req, res) => {
  try {
    const { error, value } = contactSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }
    const newContact = await contactsController.addContact(value);
    res.status(STATUS_CODES.created).json(newContact);
  } catch (error) {
    res
      .status(STATUS_CODES.error)
      .json({ message: `Server error: ${error.message}` });
  }
});

// DELETE localhost:3000/api/contacts/:id
router.delete("/:id", async (req, res) => {
  try {
    const contact = await contactsController.removeContact(req.params.id);
    if (!contact) {
      return res.status(STATUS_CODES.notFound).json({ message: "Not found" });
    }
    res.status(STATUS_CODES.deleted).json({ message: "Contact deleted" });
  } catch (error) {
    res
      .status(STATUS_CODES.error)
      .json({ message: `Server error: ${error.message}` });
  }
});

// PUT localhost:3000/api/contacts/:id
router.put("/:id", async (req, res) => {
  try {
    const { error, value } = contactSchema.validate(req.body, {
      presence: "optional",
    });
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }
    const updatedContact = await contactsController.updateContact(
      req.params.id,
      value
    );
    if (!updatedContact) {
      return res.status(STATUS_CODES.notFound).json({ message: "Not found" });
    }
    res
      .status(STATUS_CODES.success)
      .json({ message: "Contact updated", data: updatedContact });
  } catch (error) {
    res
      .status(STATUS_CODES.error)
      .json({ message: `Server error: ${error.message}` });
  }
});

// PATCH localhost:3000/api/contacts/:id/favorite
router.patch("/:id/favorite", async (req, res) => {
  try {
    const { error, value } = favoriteSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: "missing field favorite" });
    }
    const updatedContact = await contactsController.updateStatusContact(
      req.params.id,
      value
    );
    if (!updatedContact) {
      return res.status(STATUS_CODES.notFound).json({ message: "Not found" });
    }
    res
      .status(STATUS_CODES.success)
      .json({ message: "Contact updated", data: updatedContact });
  } catch (error) {
    res
      .status(STATUS_CODES.error)
      .json({ message: `Server error: ${error.message}` });
  }
});

export default router;
